package capture

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/boyvinall/trafficmon/dpi"
)

// Proto is the transport protocol of a flow.
type Proto uint8

// Supported protocols.
const (
	ProtoTCP Proto = iota
	ProtoUDP
	// ProtoICMP covers both ICMPv4 and ICMPv6: neither carries a socket, so
	// there is no attribution for a Proto of its own to distinguish.
	ProtoICMP
	// ProtoARP has no IP layer at all — its addresses come straight out of
	// the ARP payload (see flowDecoder.decode).
	ProtoARP
)

// String returns the lowercase name of p, or "?" for an unrecognised value.
func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	case ProtoARP:
		return "arp"
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

// String renders k as "proto local:port -> remote:port", for logging.
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

	// hostname is the first hostname DPI found for this flow, or "" if none
	// has been found (or DPI hasn't run for this flow yet).
	hostname string
	// hostnameAttempted is true once DPI has examined one candidate packet
	// on this flow, whether or not it found a hostname.
	hostnameAttempted bool
	// assembler joins this flow's outbound bytes into a complete TLS
	// ClientHello when its SNI extension is split across more than one TCP
	// segment. Created lazily on the first candidate packet; nil until then.
	assembler *dpi.HelloAssembler
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
	// Only advance: packets can arrive out of order, and letting one with an
	// earlier timestamp move lastSeen backwards would confuse Evict's
	// staleness check.
	if now.After(c.lastSeen) {
		c.lastSeen = now
	}
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

// Hostname returns the hostname DPI has identified for this flow's remote
// endpoint, or "" if none has been found.
func (c *ByteCounter) Hostname() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hostname
}

// SetHostname records the first hostname DPI finds for this flow.
// First-write-wins: a flow's own SNI is set once, from its own ClientHello,
// and never contradicted by anything later seen on the same flow.
func (c *ByteCounter) SetHostname(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hostname == "" {
		c.hostname = host
	}
}

// NeedsHostnameInspection reports whether DPI should still look at this
// flow's packets for a hostname.
func (c *ByteCounter) NeedsHostnameInspection() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hostname == "" && !c.hostnameAttempted
}

// MarkHostnameAttempted records that DPI has already examined one candidate
// packet on this flow, whether or not it found a hostname.
func (c *ByteCounter) MarkHostnameAttempted() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hostnameAttempted = true
}

// HelloInProgress reports whether this flow already has a hello reassembly
// under way, so Capturer.inspect knows to keep feeding it segments even past
// the packet-size threshold that started it.
func (c *ByteCounter) HelloInProgress() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.assembler != nil
}

// AddHelloSegment feeds one candidate packet's TCP payload into this flow's
// hello reassembly, creating it on first use.
func (c *ByteCounter) AddHelloSegment(seq uint32, payload []byte) (ready []byte, done bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.assembler == nil {
		c.assembler = dpi.NewHelloAssembler()
	}
	return c.assembler.Add(seq, payload)
}

// normalise folds a packet's 5-tuple onto the FlowKey that both directions of
// the connection share, using isLocal to work out which endpoint is ours. It
// reports whether the packet was inbound, and whether it could be attributed
// at all.
func normalise(src, dst netip.Addr, srcPort, dstPort uint16, proto Proto, isLocal func(netip.Addr) bool) (key FlowKey, inbound, ok bool) {
	switch {
	case isLocal(src):
		// Source-local is tested first so that loopback traffic, where both
		// ends are ours, lands on one row per local port rather than being
		// counted once at each end of the same connection.
		return FlowKey{
			LocalAddr:  src,
			LocalPort:  srcPort,
			RemoteAddr: dst,
			RemotePort: dstPort,
			Proto:      proto,
		}, false, true

	case isLocal(dst):
		return FlowKey{
			LocalAddr:  dst,
			LocalPort:  dstPort,
			RemoteAddr: src,
			RemotePort: srcPort,
			Proto:      proto,
		}, true, true

	default:
		// Neither end is ours: forwarded or multicast traffic that belongs to
		// no local socket. Dropping it beats attributing it to the wrong one.
		return FlowKey{}, false, false
	}
}
