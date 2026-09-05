package capture

import (
	"testing"
	"time"
)

func TestSYNEventRingDrainReturnsPushedAndResets(t *testing.T) {
	r := newSYNEventRing()

	e1 := SYNEvent{Iface: "en0", LocalPort: 51000, RemotePort: 443, At: time.Now()}
	e2 := SYNEvent{Iface: "en0", LocalPort: 51001, RemotePort: 443, At: time.Now()}
	r.push(e1)
	r.push(e2)

	got := r.drain()
	if len(got) != 2 || got[0] != e1 || got[1] != e2 {
		t.Fatalf("drain() = %+v, want [%+v %+v]", got, e1, e2)
	}

	if got := r.drain(); len(got) != 0 {
		t.Fatalf("drain() after drain = %+v, want empty", got)
	}
}

func TestSYNEventRingDropsOldestPastCapacity(t *testing.T) {
	r := newSYNEventRing()

	for i := range synEventRingCapacity + 10 {
		r.push(SYNEvent{LocalPort: uint16(i)})
	}

	got := r.drain()
	if len(got) != synEventRingCapacity {
		t.Fatalf("drain() has %d events, want %d", len(got), synEventRingCapacity)
	}
	// The oldest 10 were dropped, so the first entry left is LocalPort 10.
	if got[0].LocalPort != 10 {
		t.Errorf("drain()[0].LocalPort = %d, want 10 (the oldest surviving push)", got[0].LocalPort)
	}
	if last := got[len(got)-1].LocalPort; last != uint16(synEventRingCapacity+9) {
		t.Errorf("drain()[last].LocalPort = %d, want %d", last, synEventRingCapacity+9)
	}
}
