package capture

import (
	"net/netip"
	"sync"
	"time"
)

// synEventRingCapacity bounds how many pending SYN events synEventRing holds
// before the next DrainSYNEvents — past this, the oldest queued event is
// dropped to admit the newest, the same trade-off every other bounded buffer
// in this package makes for a consumer that falls behind.
const synEventRingCapacity = 4096

// SYNEvent records one outbound TCP connection attempt: a SYN seen with no
// ACK set, i.e. the opening packet of a new connection rather than one
// already established.
type SYNEvent struct {
	Iface      string
	LocalAddr  netip.Addr
	LocalPort  uint16
	RemoteAddr netip.Addr
	RemotePort uint16
	At         time.Time
}

// synEventRing is a bounded, mutex-guarded queue of SYNEvent values. push
// never blocks: past capacity it drops the oldest entry. drain swaps out the
// whole backing slice at once, matching this package's convention of
// replacing shared state wholesale rather than patching it in place.
type synEventRing struct {
	mu    sync.Mutex
	items []SYNEvent
}

// newSYNEventRing creates an empty synEventRing.
func newSYNEventRing() *synEventRing {
	return &synEventRing{items: make([]SYNEvent, 0, synEventRingCapacity)}
}

// push appends e, dropping the oldest queued event first if the ring is
// already at capacity.
func (r *synEventRing) push(e SYNEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.items) >= synEventRingCapacity {
		copy(r.items, r.items[1:])
		r.items = r.items[:len(r.items)-1]
	}
	r.items = append(r.items, e)
}

// drain returns every event queued since the last drain and resets the ring
// to empty.
func (r *synEventRing) drain() []SYNEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	items := r.items
	r.items = make([]SYNEvent, 0, synEventRingCapacity)
	return items
}
