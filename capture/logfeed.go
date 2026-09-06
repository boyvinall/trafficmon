package capture

import (
	"sync/atomic"

	"github.com/boyvinall/trafficmon/dpi"
)

// logFeedCapacity bounds each logFeed channel. Past this, sendSYN/
// sendDNSQuery drop the newest event and count it as overflow rather than
// block the packet-decode goroutine — the same non-blocking guarantee the
// drop-oldest ring buffers make, just drop-newest instead since a channel
// has no way to evict an already-queued value.
const logFeedCapacity = 1024

// logFeed fans SYN/DNS-query events out to a streaming consumer in real
// time, alongside the drop-oldest ring buffers (synEventRing, dnsQueryRing)
// a slower, tick-driven drain still serves. Unlike those rings, a full
// channel here drops the newest event rather than the oldest, and the drop
// is counted rather than silent, so a consumer that falls behind is
// visible instead of just seeing gaps.
type logFeed struct {
	syn      chan SYNEvent
	dnsQuery chan dpi.QueryFinding

	synOverflow      atomic.Uint64
	dnsQueryOverflow atomic.Uint64
}

// newLogFeed creates an empty logFeed with both channels at logFeedCapacity.
func newLogFeed() *logFeed {
	return &logFeed{
		syn:      make(chan SYNEvent, logFeedCapacity),
		dnsQuery: make(chan dpi.QueryFinding, logFeedCapacity),
	}
}

// sendSYN delivers e on the syn channel, or counts an overflow if it's
// already full. Never blocks.
func (f *logFeed) sendSYN(e SYNEvent) {
	select {
	case f.syn <- e:
	default:
		f.synOverflow.Add(1)
	}
}

// sendDNSQuery delivers q on the dnsQuery channel, or counts an overflow if
// it's already full. Never blocks.
func (f *logFeed) sendDNSQuery(q dpi.QueryFinding) {
	select {
	case f.dnsQuery <- q:
	default:
		f.dnsQueryOverflow.Add(1)
	}
}

// overflow returns the cumulative count of SYN and DNS-query events dropped
// so far because their channel was full.
func (f *logFeed) overflow() (syn, dnsQuery uint64) {
	return f.synOverflow.Load(), f.dnsQueryOverflow.Load()
}
