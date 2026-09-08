package capture

import (
	"sync"

	"github.com/boyvinall/trafficmon/dpi"
)

// dnsAnswerRingCapacity bounds how many pending DNS answer findings
// dnsAnswerRing holds before the next DrainDNSAnswers — past this, the
// oldest queued finding is dropped to admit the newest, the same trade-off
// every other bounded buffer in this package makes for a consumer that falls
// behind.
const dnsAnswerRingCapacity = 4096

// dnsAnswerRing is a bounded, mutex-guarded queue of dpi.DNSAnswerFinding
// values. push never blocks: past capacity it drops the oldest entry. drain
// swaps out the whole backing slice at once, matching this package's
// convention of replacing shared state wholesale rather than patching it in
// place.
type dnsAnswerRing struct {
	mu    sync.Mutex
	items []dpi.DNSAnswerFinding
}

// newDNSAnswerRing creates an empty dnsAnswerRing.
func newDNSAnswerRing() *dnsAnswerRing {
	return &dnsAnswerRing{items: make([]dpi.DNSAnswerFinding, 0, dnsAnswerRingCapacity)}
}

// push appends f, dropping the oldest queued finding first if the ring is
// already at capacity.
func (r *dnsAnswerRing) push(f dpi.DNSAnswerFinding) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.items) >= dnsAnswerRingCapacity {
		copy(r.items, r.items[1:])
		r.items = r.items[:len(r.items)-1]
	}
	r.items = append(r.items, f)
}

// drain returns every finding queued since the last drain and resets the
// ring to empty.
func (r *dnsAnswerRing) drain() []dpi.DNSAnswerFinding {
	r.mu.Lock()
	defer r.mu.Unlock()

	items := r.items
	r.items = make([]dpi.DNSAnswerFinding, 0, dnsAnswerRingCapacity)
	return items
}
