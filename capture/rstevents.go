package capture

import (
	"net/netip"
	"sync"
	"time"
)

// rstEventRingCapacity bounds how many pending RST events rstEventRing holds
// before the next DrainRSTEvents — past this, the oldest queued event is
// dropped to admit the newest, the same trade-off every other bounded buffer
// in this package makes for a consumer that falls behind.
const rstEventRingCapacity = 4096

// RSTEvent records one TCP RST packet seen on the wire, i.e. a connection
// being abruptly reset rather than closed with the usual FIN handshake.
type RSTEvent struct {
	Iface      string
	LocalAddr  netip.Addr
	LocalPort  uint16
	RemoteAddr netip.Addr
	RemotePort uint16
	At         time.Time
}

// rstEventRing is a bounded, mutex-guarded queue of RSTEvent values. push
// never blocks: past capacity it drops the oldest entry. drain swaps out the
// whole backing slice at once, matching this package's convention of
// replacing shared state wholesale rather than patching it in place.
type rstEventRing struct {
	mu    sync.Mutex
	items []RSTEvent
}

// newRSTEventRing creates an empty rstEventRing.
func newRSTEventRing() *rstEventRing {
	return &rstEventRing{items: make([]RSTEvent, 0, rstEventRingCapacity)}
}

// push appends e, dropping the oldest queued event first if the ring is
// already at capacity.
func (r *rstEventRing) push(e RSTEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.items) >= rstEventRingCapacity {
		copy(r.items, r.items[1:])
		r.items = r.items[:len(r.items)-1]
	}
	r.items = append(r.items, e)
}

// drain returns every event queued since the last drain and resets the ring
// to empty.
func (r *rstEventRing) drain() []RSTEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	items := r.items
	r.items = make([]RSTEvent, 0, rstEventRingCapacity)
	return items
}
