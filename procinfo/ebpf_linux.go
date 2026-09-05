//go:build linux

// Package procinfo (this file): the eBPF-backed ConnectionSource for Linux,
// replacing Poller's periodic /proc walk with a live event stream off
// tcp_v4_connect/tcp_v6_connect and the inet_sock_set_state tracepoint. See
// procinfo/bpf/{fentry,kprobe,sockstate} for the bpf2go-generated programs
// it loads.
package procinfo

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/boyvinall/trafficmon/procinfo/bpf/fentry"
	"github.com/boyvinall/trafficmon/procinfo/bpf/sockstate"
)

// ebpfAttachMode names which connect-hook mechanism ended up active, for the
// startup log line and for attach's own probe-order logic.
type ebpfAttachMode string

const (
	ebpfModeFentry ebpfAttachMode = "fentry/fexit (BTF)"
	ebpfModeKprobe ebpfAttachMode = "kprobe/kretprobe"
)

// ebpfEvent is the attach-mode-agnostic shape shared by fentry.FentryEvent,
// kprobe.KprobeEvent and sockstate.SockstateEvent. bpf2go generates each of
// those independently, one per compiled object (see
// procinfo/bpf/fentry/connect_fentry.c's file comment for why), but all
// three declare struct event identically, so every ring buffer's raw sample
// decodes into this one common type.
type ebpfEvent struct {
	SKAddr     uint64
	Pid        uint32
	IPVer      uint8
	LocalPort  uint16
	RemotePort uint16
	LocalAddr  [16]byte
	RemoteAddr [16]byte
	NewState   uint32
}

// ebpfConnKey identifies one open connection in EBPFSource's in-memory
// table. This is procinfo's own internal type -- it does not need to match
// aggregate.connKey's shape, only its spirit (a connection tuple).
//
// Deliberately excludes PID: a TCP 4-tuple alone already uniquely identifies
// a connection, and the PID an event carries is only trustworthy for some
// event sources (see handleEvent) -- keying on it risks an insert and its
// matching delete landing under two different, mismatched keys.
type ebpfConnKey struct {
	localAddr  netip.Addr
	localPort  uint16
	remoteAddr netip.Addr
	remotePort uint16
}

// ringSource pairs one attach mode's ring buffer reader with the decode
// function for its (independently bpf2go-generated) event struct.
type ringSource struct {
	reader *ringbuf.Reader
	decode func(raw []byte) (ebpfEvent, error)
}

// EBPFSource is a procinfo.ConnectionSource backed by eBPF socket-lifecycle
// events instead of a periodic /proc walk. Construct with NewEBPFSource,
// then run Connections' consumer loop via Run.
type EBPFSource struct {
	mode ebpfAttachMode

	rings   []ringSource
	closers []io.Closer // links and *Objects, closed in reverse attach order

	mu      sync.RWMutex
	conns   map[ebpfConnKey]Connection
	skToKey map[uint64]ebpfConnKey // struct sock * identity -> that connection's current key in conns
	names   map[int32]string       // cache: PID to executable name, pruned lazily

	eventCount atomic.Int64
}

// NewEBPFSource attaches the eBPF programs (fentry/fexit, falling back to
// kprobe/kretprobe) and returns a source ready for Run. Returns an error if
// neither attach mode succeeds, so the caller can fall back to
// procinfo.NewPoller() instead -- eBPF is never a hard requirement.
func NewEBPFSource() (*EBPFSource, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("procinfo: removing memlock rlimit: %w", err)
	}

	s := &EBPFSource{
		conns:   make(map[ebpfConnKey]Connection),
		skToKey: make(map[uint64]ebpfConnKey),
		names:   make(map[int32]string),
	}
	if err := s.attach(); err != nil {
		s.closeAll()
		return nil, err
	}
	s.bootstrap()

	slog.Info("procinfo: eBPF attach mode active", "mode", s.mode)
	return s, nil
}

// bootstrap seeds conns with every TCP socket already open at attach time, via
// one procfs walk (the same ListPIDs/SocketsForPID the procfs Poller itself
// uses). The tracepoints attach fires are edge-triggered on a *future* state
// transition, so a socket that reached its current state before they
// attached -- a listener bound at boot, or a connection already established
// -- would otherwise never appear until it happens to change state again.
// Called after attach so any transition racing the procfs walk is still
// captured by the ring buffer and simply overwrites this snapshot once
// consumed.
func (s *EBPFSource) bootstrap() {
	pids, err := ListPIDs()
	if err != nil {
		slog.Warn("procinfo: eBPF bootstrap: listing PIDs", "error", err)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, pid := range pids {
		socks, err := SocketsForPID(pid)
		if err != nil || len(socks) == 0 {
			continue
		}
		name := s.processNameLocked(pid)
		for _, sock := range socks {
			if sock.Proto != "tcp" {
				continue
			}
			key := ebpfConnKey{
				localAddr:  sock.LocalAddr,
				localPort:  sock.LocalPort,
				remoteAddr: sock.RemoteAddr,
				remotePort: sock.RemotePort,
			}
			s.conns[key] = Connection{
				PID:         pid,
				ProcessName: name,
				LocalAddr:   sock.LocalAddr,
				LocalPort:   sock.LocalPort,
				RemoteAddr:  sock.RemoteAddr,
				RemotePort:  sock.RemotePort,
				Proto:       sock.Proto,
				State:       sock.State,
			}
		}
	}
}

// btfAvailable reports whether the running kernel exposes its own BTF, the
// precondition for loading Tracing-type (fentry/fexit) programs at all. This
// is only a fast pre-check -- attach always falls through to the kprobe path
// on any load/attach error regardless of what this reports, since a kernel
// can expose the file and still reject a specific fentry target.
func btfAvailable() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}

// attach implements the probe order: BTF fentry/fexit preferred, falling
// back to kprobe/kretprobe (see ebpf_kprobe_*_linux.go for the two
// architecture-specific implementations of that fallback), and either way
// also attaches the inet_sock_set_state tracepoint, which is shared by both
// connect-hook modes and covers server-side (accepted) sockets neither of
// them sees.
func (s *EBPFSource) attach() error {
	var fentryErr error
	if btfAvailable() {
		slog.Info("procinfo: kernel exposes BTF, attempting fentry/fexit attach")
		if err := s.attachFentry(); err != nil {
			slog.Warn("procinfo: fentry/fexit attach failed, falling back to kprobes", "error", err)
			fentryErr = err
		} else {
			s.mode = ebpfModeFentry
		}
	} else {
		slog.Info("procinfo: no /sys/kernel/btf/vmlinux, skipping straight to kprobe fallback")
	}

	if s.mode == "" {
		if err := s.attachKprobeConnect(); err != nil {
			if fentryErr != nil {
				return fmt.Errorf("fentry/fexit attach failed (%w), kprobe fallback also failed: %w", fentryErr, err)
			}
			return fmt.Errorf("kprobe fallback failed: %w", err)
		}
		s.mode = ebpfModeKprobe
	}

	if err := s.attachSockstate(); err != nil {
		return fmt.Errorf("attaching sockstate tracepoint: %w", err)
	}
	return nil
}

func (s *EBPFSource) attachFentry() error {
	var objs fentry.FentryObjects
	if err := fentry.LoadFentryObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading fentry/fexit objects: %w", describeVerifierError(err))
	}

	l1, err := link.AttachTracing(link.TracingOptions{Program: objs.FexitTcpV4Connect})
	if err != nil {
		_ = objs.Close()
		return fmt.Errorf("attaching fexit_tcp_v4_connect: %w", err)
	}
	l2, err := link.AttachTracing(link.TracingOptions{Program: objs.FexitTcpV6Connect})
	if err != nil {
		_ = l1.Close()
		_ = objs.Close()
		return fmt.Errorf("attaching fexit_tcp_v6_connect: %w", err)
	}

	r, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		_ = l1.Close()
		_ = l2.Close()
		_ = objs.Close()
		return fmt.Errorf("opening fentry ring buffer: %w", err)
	}

	s.closers = append(s.closers, l1, l2, &objs)
	s.rings = append(s.rings, ringSource{reader: r, decode: decodeFentryEvent})
	return nil
}

// A passive bind()+listen() socket that never calls connect() still fires
// this tracepoint (oldstate=TCP_CLOSE newstate=TCP_LISTEN, confirmed via
// nc -l against a real inet_sock_set_state trace), so a listener bound after
// this attaches needs no separate handling from a connecting socket. One
// bound before this attaches is instead covered by bootstrap's procfs walk.
func (s *EBPFSource) attachSockstate() error {
	var objs sockstate.SockstateObjects
	if err := sockstate.LoadSockstateObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading sockstate tracepoint objects: %w", describeVerifierError(err))
	}

	l, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TracepointInetSockSetState, nil)
	if err != nil {
		_ = objs.Close()
		return fmt.Errorf("attaching inet_sock_set_state tracepoint: %w", err)
	}

	r, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		_ = l.Close()
		_ = objs.Close()
		return fmt.Errorf("opening sockstate ring buffer: %w", err)
	}

	s.closers = append(s.closers, l, &objs)
	s.rings = append(s.rings, ringSource{reader: r, decode: decodeSockstateEvent})
	return nil
}

// describeVerifierError surfaces the verifier's own rejection detail (which
// program, which instruction) instead of collapsing it into a generic
// wrapped error.
func describeVerifierError(err error) error {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		return fmt.Errorf("verifier rejected program: %s", fmt.Sprintf("%+v", ve))
	}
	return err
}

func decodeFentryEvent(raw []byte) (ebpfEvent, error) {
	var e fentry.FentryEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return ebpfEvent{}, err
	}
	return ebpfEvent{
		SKAddr: e.Skaddr,
		Pid:    e.Pid, IPVer: e.IpVer,
		LocalPort: e.LocalPort, RemotePort: e.RemotePort,
		LocalAddr: e.LocalAddr, RemoteAddr: e.RemoteAddr,
		NewState: e.NewState,
	}, nil
}

func decodeSockstateEvent(raw []byte) (ebpfEvent, error) {
	var e sockstate.SockstateEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return ebpfEvent{}, err
	}
	return ebpfEvent{
		SKAddr: e.Skaddr,
		Pid:    e.Pid, IPVer: e.IpVer,
		LocalPort: e.LocalPort, RemotePort: e.RemotePort,
		LocalAddr: e.LocalAddr, RemoteAddr: e.RemoteAddr,
		NewState: e.NewState,
	}, nil
}

// Run consumes every attached ring buffer, one goroutine each, until ctx is
// cancelled. Each event either inserts/updates the connection it describes
// or, on a terminal TCP state, removes it -- see terminalTCPState.
func (s *EBPFSource) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, rs := range s.rings {
		wg.Add(1)
		go func(rs ringSource) {
			defer wg.Done()
			s.consume(rs)
		}(rs)
	}

	<-ctx.Done()
	for _, rs := range s.rings {
		if err := rs.reader.Close(); err != nil {
			slog.Warn("procinfo: closing eBPF ring buffer reader", "error", err)
		}
	}
	wg.Wait()
	s.closeAll()
	return ctx.Err()
}

func (s *EBPFSource) consume(rs ringSource) {
	for {
		record, err := rs.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			slog.Warn("procinfo: reading eBPF ring buffer", "error", err)
			continue
		}

		ev, err := rs.decode(record.RawSample)
		if err != nil {
			slog.Warn("procinfo: decoding eBPF ring buffer event", "error", err)
			continue
		}
		s.handleEvent(ev)
	}
}

// handleEvent applies one connect/state-change event to the in-memory
// connection table: insert/update on a live state, remove on a terminal one.
//
// The connect-hook events (fentry/fexit, kprobe) fire synchronously in the
// connecting process's own syscall context, so their Pid is trustworthy.
// The sockstate tracepoint fires on every TCP state transition, including
// ones driven by an incoming packet in softirq context -- there, "the
// current task" bpf_get_current_pid_tgid() reads is whatever happened to be
// running, not the socket's owning process, so its Pid can be wrong or a
// kernel thread's. handleEvent therefore never lets a later event's Pid
// overwrite a PID already recorded for a still-open connection.
func (s *EBPFSource) handleEvent(ev ebpfEvent) {
	s.eventCount.Add(1)

	localAddr, ok := addrFromEventBytes(ev.IPVer, ev.LocalAddr)
	if !ok {
		return
	}
	remoteAddr, ok := addrFromEventBytes(ev.IPVer, ev.RemoteAddr)
	if !ok {
		return
	}

	key := ebpfConnKey{
		localAddr:  localAddr,
		localPort:  ev.LocalPort,
		remoteAddr: remoteAddr,
		remotePort: ev.RemotePort,
	}
	state := tcpStateName(int(ev.NewState))

	s.mu.Lock()
	defer s.mu.Unlock()

	// oldKey, when present, is where this same struct sock's previous event
	// landed -- found via SKAddr rather than key, since an early event in a
	// connection's life (SYN_SENT before the kernel autobinds a local port,
	// SYN_RECV before a child socket's remote address is populated) can
	// carry an incomplete tuple that a later event on the same socket then
	// corrects. Without this indirection the corrected entry lands under a
	// new key and the original incomplete one is never deleted, since
	// terminalTCPState's own delete only ever matches the *current* event's
	// key.
	oldKey, hadOld := s.skToKey[ev.SKAddr]

	if terminalTCPState(state) {
		if hadOld {
			delete(s.conns, oldKey)
			delete(s.skToKey, ev.SKAddr)
		} else {
			delete(s.conns, key)
		}
		return
	}

	pid := int32(ev.Pid)
	if hadOld {
		if existing, ok := s.conns[oldKey]; ok {
			pid = existing.PID
		}
		if oldKey != key {
			delete(s.conns, oldKey)
		}
	} else if existing, ok := s.conns[key]; ok {
		pid = existing.PID
	}

	s.conns[key] = Connection{
		PID:         pid,
		ProcessName: s.processNameLocked(pid),
		LocalAddr:   localAddr,
		LocalPort:   ev.LocalPort,
		RemoteAddr:  remoteAddr,
		RemotePort:  ev.RemotePort,
		Proto:       "tcp",
		State:       state,
	}
	s.skToKey[ev.SKAddr] = key
}

// processNameLocked resolves and caches pid's executable name. Must be
// called with s.mu held. Only a resolved name is cached: caching a failed
// lookup would turn one transient error into a permanent "?" for the PID's
// whole life, the same rule Poller.poll applies to its own name cache.
func (s *EBPFSource) processNameLocked(pid int32) string {
	if name, ok := s.names[pid]; ok {
		return name
	}
	name, err := ProcessName(pid)
	if err != nil {
		return "?"
	}
	s.names[pid] = name
	return name
}

// terminalTCPState reports whether state is one of the kernel's
// winding-down TCP states, mirroring aggregate.closingTCPState's list
// (aggregate/aggregator.go) in spirit: CLOSE_WAIT, LAST_ACK, CLOSING,
// TIME_WAIT, both FIN_WAIT states, and the fully-closed state. The literal
// spellings differ from aggregate's switch because they're keyed to
// tcpStateName's own Linux-native output ("FIN_WAIT1"/"CLOSE", not Darwin's
// "FIN_WAIT_1"/"CLOSED") -- the same strings this source puts on
// Connection.State and that aggregate.closed will see for a Linux
// Connection, so the two agree on when a connection is gone even though
// their string constants aren't byte-identical.
func terminalTCPState(state string) bool {
	switch state {
	case "CLOSE_WAIT", "LAST_ACK", "CLOSING", "TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2", "CLOSE":
		return true
	default:
		return false
	}
}

// addrFromEventBytes converts an event's fixed 16-byte address field to a
// netip.Addr, given the IP version the event itself recorded.
func addrFromEventBytes(ipVer uint8, raw [16]byte) (netip.Addr, bool) {
	switch ipVer {
	case 4:
		var b [4]byte
		copy(b[:], raw[:4])
		return netip.AddrFrom4(b), true
	case 6:
		return netip.AddrFrom16(raw).Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

// EventCount returns the total number of eBPF ring-buffer events processed
// since this source was created, across every attached ring buffer
// (fentry/fexit or kprobe connect events plus sockstate transitions).
// Benchmarks use this to measure attribution completeness against
// procinfo.Poller's per-tick connection count.
func (s *EBPFSource) EventCount() int64 {
	return s.eventCount.Load()
}

// Connections returns a snapshot copy of the currently open connections, as
// last reported by the eBPF event stream. Satisfies procinfo.ConnectionSource.
func (s *EBPFSource) Connections() []Connection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Connection, 0, len(s.conns))
	for _, c := range s.conns {
		out = append(out, c)
	}
	return out
}

// closeAll releases every attached link and loaded collection, in reverse
// attach order, logging rather than failing on an individual close error
// since this only ever runs during cleanup.
func (s *EBPFSource) closeAll() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		if err := s.closers[i].Close(); err != nil {
			slog.Warn("procinfo: closing eBPF resource", "error", err)
		}
	}
}
