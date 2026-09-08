package tui

import (
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/boyvinall/trafficmon/aggregate"
	"github.com/boyvinall/trafficmon/capture"
	"github.com/boyvinall/trafficmon/dpi"
)

func TestEventRingDropsOldestAtCapacity(t *testing.T) {
	var r eventRing
	for i := range eventRingCapacity + 10 {
		r.push(eventRecord{Info: strconv.Itoa(i)})
	}

	items := r.slice()
	if len(items) != eventRingCapacity {
		t.Fatalf("len = %d, want %d", len(items), eventRingCapacity)
	}
	if items[0].Info != "10" {
		t.Errorf("oldest surviving item = %q, want %q (the first 10 pushed should have been dropped)", items[0].Info, "10")
	}
	if want := strconv.Itoa(eventRingCapacity + 9); items[len(items)-1].Info != want {
		t.Errorf("newest item = %q, want %q", items[len(items)-1].Info, want)
	}
}

func TestEventRingPreservesOrder(t *testing.T) {
	var r eventRing
	for i := range 5 {
		r.push(eventRecord{Info: strconv.Itoa(i)})
	}

	items := r.slice()
	if got := r.len(); got != 5 {
		t.Fatalf("len() = %d, want 5", got)
	}
	for i, rec := range items {
		if want := strconv.Itoa(i); rec.Info != want {
			t.Errorf("item %d = %q, want %q", i, rec.Info, want)
		}
	}
}

func TestAppendEventsMergesStreamsByTimestamp(t *testing.T) {
	m := newTestModel(nil, 100, 20)

	snap := aggregate.Snapshot{
		SYNEvents: []capture.SYNEvent{{
			Iface: "en0", LocalAddr: netip.MustParseAddr("192.168.1.10"), LocalPort: 51000,
			RemoteAddr: netip.MustParseAddr("1.2.3.4"), RemotePort: 443, At: testNow.Add(2 * time.Second),
		}},
		RSTEvents: []capture.RSTEvent{{
			Iface: "en0", LocalAddr: netip.MustParseAddr("192.168.1.10"), LocalPort: 51001,
			RemoteAddr: netip.MustParseAddr("5.6.7.8"), RemotePort: 443, At: testNow.Add(4 * time.Second),
		}},
		DNSQueries: []dpi.QueryFinding{{
			Name: "example.com", QType: "A", ClientAddr: "192.168.1.10", ServerAddr: "8.8.8.8",
			At: testNow.Add(1 * time.Second),
		}},
		DNSErrors: []dpi.DNSErrorFinding{{
			Name: "bad.example", QType: "A", RCode: "NXDOMAIN", ServerAddr: "8.8.8.8",
			At: testNow.Add(3 * time.Second),
		}},
	}

	m.appendEvents(snap)

	items := m.events.slice()
	if len(items) != 4 {
		t.Fatalf("len = %d, want 4", len(items))
	}

	want := []eventKind{eventDNSQuery, eventSYN, eventDNSError, eventRST}
	for i, k := range want {
		if items[i].Kind != k {
			t.Errorf("item %d kind = %v, want %v (streams should be merged in timestamp order)", i, items[i].Kind, k)
		}
	}

	if got := items[1].Local; got != "192.168.1.10:51000" {
		t.Errorf("SYN local = %q, want %q", got, "192.168.1.10:51000")
	}
	if got := items[1].Remote; got != "1.2.3.4:443" {
		t.Errorf("SYN remote = %q, want %q", got, "1.2.3.4:443")
	}
	if got := items[1].Info; got != "en0" {
		t.Errorf("SYN info = %q, want the capturing interface %q", got, "en0")
	}

	if got := items[0].Info; got != "example.com (A)" {
		t.Errorf("DNS query info = %q, want %q", got, "example.com (A)")
	}
	if got := items[2].Info; got != "bad.example (A) NXDOMAIN" {
		t.Errorf("DNS error info = %q, want %q", got, "bad.example (A) NXDOMAIN")
	}
	if got := items[2].Local; got != "" {
		t.Errorf("DNS error local = %q, want blank (no client address at that layer)", got)
	}
}

func TestAppendEventsRetainsAcrossRefreshesEvenThoughSnapshotDoesNot(t *testing.T) {
	m := newTestModel(nil, 100, 20)

	m.appendEvents(aggregate.Snapshot{
		SYNEvents: []capture.SYNEvent{{At: testNow}},
	})
	m.appendEvents(aggregate.Snapshot{
		SYNEvents: []capture.SYNEvent{{At: testNow.Add(time.Second)}},
	})

	if got := m.events.len(); got != 2 {
		t.Errorf("events.len() = %d, want 2 (each appendEvents call should add, not replace)", got)
	}
}

func TestEventKindStrings(t *testing.T) {
	tests := map[eventKind]string{
		eventSYN:      "SYN",
		eventRST:      "RST",
		eventDNSQuery: "DNS Q",
		eventDNSError: "DNS ERR",
	}
	for k, want := range tests {
		if got := k.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", k, got, want)
		}
	}
}

func TestFormatEventRow(t *testing.T) {
	rec := eventRecord{
		At: testNow, Kind: eventSYN,
		Local: "1.2.3.4:5000", Remote: "5.6.7.8:443", Info: "en0",
	}

	got := formatEventRow(rec)
	want := []string{testNow.Format(eventTimeFormat), "SYN", "1.2.3.4:5000", "5.6.7.8:443", "en0"}
	if len(got) != len(want) {
		t.Fatalf("formatEventRow = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("column %d = %q, want %q", i, got[i], want[i])
		}
	}
}
