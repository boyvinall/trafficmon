package capture

import (
	"testing"
	"time"

	"github.com/boyvinall/trafficmon/dpi"
)

func TestDNSErrorRingDrainReturnsPushedItemsAndResets(t *testing.T) {
	r := newDNSErrorRing()
	now := time.Now()

	r.push(dpi.DNSErrorFinding{Name: "a.example.com", RCode: "NXDOMAIN", ServerAddr: "8.8.8.8", At: now})
	r.push(dpi.DNSErrorFinding{Name: "b.example.com", RCode: "NXDOMAIN", ServerAddr: "8.8.8.8", At: now})

	got := r.drain()
	want := []dpi.DNSErrorFinding{
		{Name: "a.example.com", RCode: "NXDOMAIN", ServerAddr: "8.8.8.8", At: now},
		{Name: "b.example.com", RCode: "NXDOMAIN", ServerAddr: "8.8.8.8", At: now},
	}
	if len(got) != len(want) {
		t.Fatalf("drain() = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("drain()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	if got := r.drain(); len(got) != 0 {
		t.Fatalf("drain() after a drain = %+v, want empty", got)
	}
}

func TestDNSErrorRingDropsOldestOnOverflow(t *testing.T) {
	r := newDNSErrorRing()

	for i := 0; i < dnsErrorRingCapacity+10; i++ {
		r.push(dpi.DNSErrorFinding{Name: string(rune('a' + i%26))})
	}

	got := r.drain()
	if len(got) != dnsErrorRingCapacity {
		t.Fatalf("drain() returned %d items, want %d", len(got), dnsErrorRingCapacity)
	}

	wantFirst := dpi.DNSErrorFinding{Name: string(rune('a' + 10%26))}
	if got[0] != wantFirst {
		t.Errorf("drain()[0] = %+v, want %+v (the 10 oldest pushes should have been dropped)", got[0], wantFirst)
	}
}
