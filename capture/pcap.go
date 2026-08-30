package capture

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gopacket/gopacket/pcap"
)

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

// Run opens the interface and decodes packets until ctx is cancelled.
//
// TODO(milestone 1): pcap.OpenLive, set the BPF filter to "ip and (tcp or
// udp)", then decode each packet to a FlowKey and feed the ByteCounter.
func (c *Capturer) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
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

// DefaultInterface resolves the interface backing the default route, mirroring
// what `route get default` reports.
//
// TODO(milestone 1): parse the default route instead of taking the first
// non-loopback device libpcap offers.
func DefaultInterface() (string, error) {
	names, err := ListInterfaces()
	if err != nil {
		return "", err
	}
	for _, n := range names {
		if n != "lo0" {
			return n, nil
		}
	}
	return "", fmt.Errorf("no capturable interface found")
}
