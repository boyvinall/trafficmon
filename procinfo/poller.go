package procinfo

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// PollInterval is how often the full PID/fd walk runs. Enumerating every
// process's descriptors is expensive, so this is deliberately slower than the
// packet capture loop.
const PollInterval = time.Second

// Process identifies the owner of a socket.
type Process struct {
	PID  int32
	Name string
}

// portKey identifies a bound local port together with its transport
// protocol. Two unrelated processes can legitimately hold the same port
// number on different protocols (say a resolver on UDP/53 alongside a server
// on TCP/53); keying on the number alone would let one silently overwrite the
// other in the map.
type portKey struct {
	port  uint16
	proto string
}

// Connection is one open socket, as enumerated directly from the kernel (see
// SocketsForPID) together with the process that owns it.
//
// Unlike the port map Lookup and Snapshot expose, which only says who
// currently owns a local port, Connections is the full list: it is what lets
// a row exist in the UI purely because a socket is open, whether or not it
// has ever carried traffic.
type Connection struct {
	PID         int32
	ProcessName string

	LocalAddr  netip.Addr
	LocalPort  uint16
	RemoteAddr netip.Addr
	RemotePort uint16
	Proto      string // "tcp" or "udp"
	// State is the TCP connection's kernel state, or "" for UDP.
	State string
}

// Poller periodically rebuilds the local-port to process mapping and the
// full open-connection list.
type Poller struct {
	mu    sync.RWMutex
	ports map[portKey]Process
	names map[int32]string // cache: PID to executable name, pruned each poll
	conns []Connection
}

// NewPoller returns an idle Poller. Call Run to start polling.
func NewPoller() *Poller {
	return &Poller{
		ports: make(map[portKey]Process),
		names: make(map[int32]string),
	}
}

// Run polls until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) error {
	t := time.NewTicker(PollInterval)
	defer t.Stop()

	for {
		if err := p.poll(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// poll rebuilds both the port map and the process-name cache from scratch.
// Building the port map fresh (rather than patching) is what makes port reuse
// safe: a recycled port always resolves to its current owner. The name cache
// is pruned the same way each poll, keeping only the PIDs seen in this walk,
// so a PID that has since exited does not go on lending its old name to
// whatever reuses that number next.
//
// The map is keyed on local port and protocol: two processes can legitimately
// hold the same port number on different protocols (UDP/53 vs TCP/53), and
// keying on the number alone would let one silently clobber the other. Two
// processes can also legitimately hold the same port and protocol on
// different local addresses (a listener bound per-interface, or SO_REUSEPORT
// across a worker pool), in which case the last PID walked wins.
//
// The PID/fd walk itself runs without holding the lock; only the final map
// swap takes the exclusive lock, so a Lookup/Snapshot reader is blocked for a
// map assignment rather than the whole sweep.
func (p *Poller) poll() error {
	pids, err := ListPIDs()
	if err != nil {
		return err
	}

	p.mu.RLock()
	oldNames := p.names
	p.mu.RUnlock()

	ports := make(map[portKey]Process, len(pids))
	names := make(map[int32]string, len(oldNames))
	var conns []Connection

	for _, pid := range pids {
		socks, err := SocketsForPID(pid)
		if err != nil {
			// Processes come and go mid-walk, and some are simply not
			// inspectable -- a hardened-runtime process (many EDR/security
			// agents, e.g. a System Extension, deliberately block fd
			// introspection as self-protection) can refuse this even to
			// root. Skip rather than abandoning the whole poll, but log the
			// reason at debug level: otherwise a PID that is persistently
			// unattributable is indistinguishable from one that legitimately
			// owns no sockets, and every one of its flows silently lands in
			// UnknownProcess with no way to tell why.
			slog.Debug("procinfo: pid not inspectable, skipping", "pid", pid, "err", err)
			continue
		}
		if len(socks) == 0 {
			continue
		}

		name, ok := oldNames[pid]
		if !ok {
			if resolved, err := ProcessName(pid); err == nil {
				name = resolved
			} else {
				name = "?"
			}
		}
		// Only a resolved name is carried into the next poll: caching "?"
		// would turn one transient lookup failure into a permanent one for
		// the life of the PID.
		if name != "?" {
			names[pid] = name
		}

		for _, s := range socks {
			ports[portKey{port: s.LocalPort, proto: s.Proto}] = Process{PID: pid, Name: name}
			conns = append(conns, Connection{
				PID:         pid,
				ProcessName: name,
				LocalAddr:   s.LocalAddr,
				LocalPort:   s.LocalPort,
				RemoteAddr:  s.RemoteAddr,
				RemotePort:  s.RemotePort,
				Proto:       s.Proto,
				State:       s.State,
			})
		}
	}

	p.mu.Lock()
	p.ports = ports
	p.names = names
	p.conns = conns
	p.mu.Unlock()

	return nil
}

// Lookup returns the process currently owning localPort for the given
// transport protocol.
func (p *Poller) Lookup(localPort uint16, proto string) (Process, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	proc, ok := p.ports[portKey{port: localPort, proto: proto}]
	return proc, ok
}

// Snapshot returns a copy of the current port map for the aggregator to join
// against. The result is keyed on port number alone, so if two processes hold
// the same port on different protocols only one is represented; Lookup, which
// takes the protocol into account, does not have that limitation.
func (p *Poller) Snapshot() map[uint16]Process {
	p.mu.RLock()
	defer p.mu.RUnlock()

	out := make(map[uint16]Process, len(p.ports))
	for k, v := range p.ports {
		out[k.port] = v
	}
	return out
}

// Connections returns every socket seen in the most recently completed
// poll, across every process. The aggregator uses this, not Snapshot, to
// decide which rows exist: a row is present because a socket is open, not
// because traffic has been captured for it.
func (p *Poller) Connections() []Connection {
	p.mu.RLock()
	defer p.mu.RUnlock()

	out := make([]Connection, len(p.conns))
	copy(out, p.conns)
	return out
}
