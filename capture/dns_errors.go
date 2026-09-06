package capture

import (
	"sync"

	"github.com/boyvinall/trafficmon/dpi"
)

// dnsErrorRingCapacity bounds how many pending DNS error findings dnsErrorRing
// holds before the next DrainDNSErrors — past this, the oldest queued
// finding is dropped to admit the newest, the same trade-off every other
// bounded buffer in this package makes for a consumer that falls behind.
const dnsErrorRingCapacity = 4096

// dnsErrorRing is a bounded, mutex-guarded queue of dpi.DNSErrorFinding
// values. push never blocks: past capacity it drops the oldest entry. drain
// swaps out the whole backing slice at once, matching this package's
// convention of replacing shared state wholesale rather than patching it in
// place.
type dnsErrorRing struct {
	mu    sync.Mutex
	items []dpi.DNSErrorFinding
}

// newDNSErrorRing creates an empty dnsErrorRing.
func newDNSErrorRing() *dnsErrorRing {
	return &dnsErrorRing{items: make([]dpi.DNSErrorFinding, 0, dnsErrorRingCapacity)}
}

// push appends f, dropping the oldest queued finding first if the ring is
// already at capacity.
func (r *dnsErrorRing) push(f dpi.DNSErrorFinding) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.items) >= dnsErrorRingCapacity {
		copy(r.items, r.items[1:])
		r.items = r.items[:len(r.items)-1]
	}
	r.items = append(r.items, f)
}

// drain returns every finding queued since the last drain and resets the
// ring to empty.
func (r *dnsErrorRing) drain() []dpi.DNSErrorFinding {
	r.mu.Lock()
	defer r.mu.Unlock()

	items := r.items
	r.items = make([]dpi.DNSErrorFinding, 0, dnsErrorRingCapacity)
	return items
}
