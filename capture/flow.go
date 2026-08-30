package capture

import (
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Proto is the transport protocol of a flow.
type Proto uint8

// Supported transport protocols.
const (
	ProtoTCP Proto = iota
	ProtoUDP
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	default:
		return "?"
	}
}

// FlowKey identifies one bidirectional connection. Direction is normalised at
// construction time so that inbound and outbound packets of the same
// connection map onto a single entry.
type FlowKey struct {
	LocalAddr  netip.Addr
	LocalPort  uint16
	RemoteAddr netip.Addr
	RemotePort uint16
	Proto      Proto
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s %s:%d -> %s:%d",
		k.Proto,
		k.LocalAddr, k.LocalPort,
		k.RemoteAddr, k.RemotePort)
}

// rateWindow is the span over which the live throughput rate is averaged.
const rateWindow = 5 * time.Second

// rateBuckets is the number of one-second buckets covering rateWindow.
const rateBuckets = 5

// ByteCounter accumulates traffic for a single flow: monotonic totals since
// process start, plus a small ring of per-second buckets used to derive the
// live rate.
type ByteCounter struct {
	mu sync.Mutex

	bytesIn  uint64
	bytesOut uint64

	// Ring of per-second buckets. bucketStart is the start of the second
	// currently covered by bucket[head].
	in          [rateBuckets]uint64
	out         [rateBuckets]uint64
	head        int
	bucketStart time.Time

	lastSeen time.Time
}

// advance rolls the ring forward to the second containing now, zeroing every
// bucket it passes over. Caller must hold c.mu.
func (c *ByteCounter) advance(now time.Time) {
	sec := now.Truncate(time.Second)

	if c.bucketStart.IsZero() {
		c.bucketStart = sec
		return
	}

	steps := int(sec.Sub(c.bucketStart) / time.Second)
	if steps <= 0 {
		return
	}

	if steps >= rateBuckets {
		// Idle for longer than the whole window: everything is stale.
		c.in = [rateBuckets]uint64{}
		c.out = [rateBuckets]uint64{}
	} else {
		for range steps {
			c.head = (c.head + 1) % rateBuckets
			c.in[c.head] = 0
			c.out[c.head] = 0
		}
	}
	c.bucketStart = sec
}

// Add records n bytes seen for the flow at time now. inbound reports whether
// the packet was travelling towards the local endpoint.
func (c *ByteCounter) Add(now time.Time, n uint64, inbound bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.advance(now)

	if inbound {
		c.bytesIn += n
		c.in[c.head] += n
	} else {
		c.bytesOut += n
		c.out[c.head] += n
	}
	c.lastSeen = now
}

// Totals returns the cumulative bytes in and out since process start.
func (c *ByteCounter) Totals() (in, out uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesIn, c.bytesOut
}

// Rates returns the live throughput in bytes/sec, averaged over rateWindow.
func (c *ByteCounter) Rates(now time.Time) (in, out float64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Expire stale buckets first, so a flow that has stopped reads as zero
	// rather than holding its last rate.
	c.advance(now)

	var sumIn, sumOut uint64
	for i := range rateBuckets {
		sumIn += c.in[i]
		sumOut += c.out[i]
	}

	secs := rateWindow.Seconds()
	return float64(sumIn) / secs, float64(sumOut) / secs
}

// LastSeen reports when this flow last carried a packet.
func (c *ByteCounter) LastSeen() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastSeen
}
