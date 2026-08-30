package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/sync/errgroup"
)

// bpfFilter keeps the kernel from handing us anything we cannot attribute to a
// socket: only IPv4/IPv6 carrying TCP or UDP survives it.
const bpfFilter = "(ip or ip6) and (tcp or udp)"

// readTimeout bounds how long one read blocks inside libpcap.
//
// pcap.BlockForever would park the reader in libpcap while holding the
// handle's mutex, so a Close from another goroutine could not interrupt it and
// a quiet interface would keep Run alive long past ctx being cancelled. A
// short timeout lets the loop come up for air and check ctx instead.
const readTimeout = 250 * time.Millisecond

// Config controls live packet capture.
type Config struct {
	// Interface to capture on. Empty means auto-detect from the default route.
	Interface string

	// IncludeLoopback captures lo0 traffic as well as the primary interface.
	IncludeLoopback bool

	// SnapLen is the per-packet capture length. Headers only is enough: the
	// payload length comes from the IP header, not the captured bytes.
	SnapLen int
}

// DefaultConfig returns the capture defaults.
func DefaultConfig() Config {
	return Config{SnapLen: 128}
}

// Capturer owns the pcap handle and the flow table it feeds.
type Capturer struct {
	cfg Config

	mu    sync.RWMutex
	flows map[FlowKey]*ByteCounter
}

// New creates a Capturer. It does not open the interface; call Run for that.
func New(cfg Config) *Capturer {
	return &Capturer{
		cfg:   cfg,
		flows: make(map[FlowKey]*ByteCounter),
	}
}

// Run opens the interface and decodes packets into the flow table until ctx is
// cancelled, at which point it returns ctx.Err().
func (c *Capturer) Run(ctx context.Context) error {
	ifaces := []string{c.cfg.Interface}
	if c.cfg.IncludeLoopback && c.cfg.Interface != loopbackInterface {
		// Loopback traffic never reaches the primary interface, so it needs a
		// handle of its own feeding the same flow map.
		ifaces = append(ifaces, loopbackInterface)
	}

	locals, err := localAddrSet(ifaces)
	if err != nil {
		return err
	}
	isLocal := func(a netip.Addr) bool {
		_, found := locals[a]
		return found
	}

	g, ctx := errgroup.WithContext(ctx)
	for _, iface := range ifaces {
		g.Go(func() error { return c.captureOn(ctx, iface, isLocal) })
	}
	return g.Wait()
}

// captureOn drives one pcap handle. It owns that handle for its whole life, so
// nothing else can close it out from under the read in progress.
func (c *Capturer) captureOn(ctx context.Context, iface string, isLocal func(netip.Addr) bool) error {
	// Promiscuous mode stays off: we only want traffic this host is an
	// endpoint of, and anything else would be attributed to no local socket.
	handle, err := pcap.OpenLive(iface, int32(c.cfg.SnapLen), false, readTimeout)
	if err != nil {
		return fmt.Errorf("open %s: %w", iface, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return fmt.Errorf("set filter on %s: %w", iface, err)
	}

	dec, err := newFlowDecoder(handle.LinkType())
	if err != nil {
		return fmt.Errorf("decode %s: %w", iface, err)
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		// Zero-copy is safe here because everything kept from the packet —
		// addresses, ports, lengths — is copied into values before the next
		// read invalidates the buffer.
		data, ci, err := handle.ZeroCopyReadPacketData()
		switch {
		case err == nil:
		case errors.Is(err, pcap.NextErrorTimeoutExpired):
			continue
		case errors.Is(err, io.EOF):
			return fmt.Errorf("capture on %s ended", iface)
		default:
			return fmt.Errorf("read from %s: %w", iface, err)
		}

		info, ok := dec.decode(data)
		if !ok {
			continue
		}
		key, inbound, ok := normalise(info.Src, info.Dst, info.SrcPort, info.DstPort, info.Proto, isLocal)
		if !ok {
			continue
		}

		// libpcap timestamps come from the kernel at capture time, which is
		// closer to when the bytes moved than any clock read here would be.
		ts := ci.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		c.record(key, ts, info.Bytes, inbound)
	}
}

// record credits n bytes to a flow, creating its counter on first sight. The
// map lock is released before the counter is touched so that a Snapshot never
// waits on per-flow bookkeeping.
func (c *Capturer) record(key FlowKey, ts time.Time, n uint64, inbound bool) {
	c.mu.RLock()
	ctr := c.flows[key]
	c.mu.RUnlock()

	if ctr == nil {
		c.mu.Lock()
		// Re-check: another interface's goroutine may have created it while
		// the read lock was down.
		if ctr = c.flows[key]; ctr == nil {
			ctr = &ByteCounter{}
			c.flows[key] = ctr
		}
		c.mu.Unlock()
	}

	ctr.Add(ts, n, inbound)
}

// Snapshot returns a point-in-time copy of every flow's counters, for the
// aggregator to join against the process map.
func (c *Capturer) Snapshot(now time.Time) map[FlowKey]FlowStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make(map[FlowKey]FlowStats, len(c.flows))
	for k, ctr := range c.flows {
		in, outB := ctr.Totals()
		rIn, rOut := ctr.Rates(now)
		out[k] = FlowStats{
			BytesIn:    in,
			BytesOut:   outB,
			RateInBps:  rIn,
			RateOutBps: rOut,
			LastSeen:   ctr.LastSeen(),
		}
	}
	return out
}

// FlowStats is an immutable snapshot of one flow's counters.
type FlowStats struct {
	BytesIn    uint64
	BytesOut   uint64
	RateInBps  float64
	RateOutBps float64
	LastSeen   time.Time
}

// ListInterfaces returns the interfaces libpcap can capture on. Requires root.
func ListInterfaces() ([]string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("pcap.FindAllDevs: %w", err)
	}

	names := make([]string, 0, len(devs))
	for _, d := range devs {
		names = append(names, d.Name)
	}
	return names, nil
}
