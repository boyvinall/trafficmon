package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/sync/errgroup"
)

// bpfFilter keeps the kernel from handing us anything the decoder cannot use:
// TCP/UDP (attributable to a socket), plus ICMP and ARP, which are shown with
// no process attribution since neither has one.
const bpfFilter = "tcp or udp or icmp or icmp6 or arp"

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

// Run opens the interface and decodes packets into the flow table. If ctx is
// cancelled or its deadline expires, Run returns ctx.Err(); it can also
// return earlier than that with a different error — an invalid SnapLen, a
// failure to open the interface or set the BPF filter, an unsupported link
// type, or a read error (including the handle reaching EOF) all cause it to
// return before ctx is done.
func (c *Capturer) Run(ctx context.Context) error {
	if c.cfg.SnapLen < 1 || c.cfg.SnapLen > math.MaxInt32 {
		return fmt.Errorf("SnapLen %d out of range [1, %d]", c.cfg.SnapLen, math.MaxInt32)
	}

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

// Evict drops every flow last seen before the cutoff and reports how many it
// removed.
//
// Nothing else ever removes a flow, so without this the table grows by one
// counter per connection the host has ever made and never shrinks — a leak
// that only shows up on a long run. The aggregator calls it with the grace
// period's cutoff, once a flow is too stale to appear in the UI at all: a
// packet arriving on an evicted flow afterwards simply starts a fresh counter,
// which is the same thing the UI would show for a brand new connection.
func (c *Capturer) Evict(before time.Time) int {
	// Snapshot the candidate keys under a read lock first: LastSeen on every
	// counter would otherwise serialise against the write lock the hot record
	// path also needs, for the whole sweep rather than just the deletions.
	c.mu.RLock()
	stale := make([]FlowKey, 0, len(c.flows))
	for k, ctr := range c.flows {
		if ctr.LastSeen().Before(before) {
			stale = append(stale, k)
		}
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	n := 0
	for _, k := range stale {
		// Re-check staleness under the write lock: a flow may have seen a
		// packet between the snapshot above and taking this lock, and that
		// activity must not be discarded.
		ctr, ok := c.flows[k]
		if !ok || !ctr.LastSeen().Before(before) {
			continue
		}
		delete(c.flows, k)
		n++
	}
	return n
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
