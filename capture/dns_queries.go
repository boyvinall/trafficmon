package capture

import (
	"sync"

	"github.com/boyvinall/trafficmon/dpi"
)

// dnsQueryRingCapacity bounds how many pending DNS query findings dnsQueryRing
// holds before the next DrainDNSQueries — past this, the oldest queued
// finding is dropped to admit the newest, the same trade-off every other
// bounded buffer in this package makes for a consumer that falls behind.
const dnsQueryRingCapacity = 4096

// dnsQueryRing is a bounded, mutex-guarded queue of dpi.QueryFinding values.
// push never blocks: past capacity it drops the oldest entry. drain swaps
// out the whole backing slice at once, matching this package's convention
// of replacing shared state wholesale rather than patching it in place.
type dnsQueryRing struct {
	mu    sync.Mutex
	items []dpi.QueryFinding
}

// newDNSQueryRing creates an empty dnsQueryRing.
func newDNSQueryRing() *dnsQueryRing {
	return &dnsQueryRing{items: make([]dpi.QueryFinding, 0, dnsQueryRingCapacity)}
}

// push appends f, dropping the oldest queued finding first if the ring is
// already at capacity.
func (r *dnsQueryRing) push(f dpi.QueryFinding) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.items) >= dnsQueryRingCapacity {
		copy(r.items, r.items[1:])
		r.items = r.items[:len(r.items)-1]
	}
	r.items = append(r.items, f)
}

// drain returns every finding queued since the last drain and resets the
// ring to empty.
func (r *dnsQueryRing) drain() []dpi.QueryFinding {
	r.mu.Lock()
	defer r.mu.Unlock()

	items := r.items
	r.items = make([]dpi.QueryFinding, 0, dnsQueryRingCapacity)
	return items
}
