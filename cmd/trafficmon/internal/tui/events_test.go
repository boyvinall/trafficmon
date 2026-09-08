package tui

import (
	"net/netip"
	"slices"
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
		DNSAnswers: []dpi.DNSAnswerFinding{{
			Name: "good.example", QType: "A", Answer: "9.9.9.9", ServerAddr: "8.8.8.8",
			At: testNow.Add(5 * time.Second),
		}},
	}

	m.appendEvents(snap)

	items := m.events.slice()
	if len(items) != 5 {
		t.Fatalf("len = %d, want 5", len(items))
	}

	want := []eventKind{eventDNSQuery, eventSYN, eventDNSError, eventRST, eventDNSAnswer}
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
	if got := items[4].Info; got != "good.example (A) -> 9.9.9.9" {
		t.Errorf("DNS answer info = %q, want %q", got, "good.example (A) -> 9.9.9.9")
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

func TestAppendEventsAutoScrollsWhenCursorFollowsLatest(t *testing.T) {
	m := newTestModel(nil, 100, 20)

	m.appendEvents(aggregate.Snapshot{SYNEvents: []capture.SYNEvent{{At: testNow}}})
	m.appendEvents(aggregate.Snapshot{SYNEvents: []capture.SYNEvent{{At: testNow.Add(time.Second)}}})

	if got, want := m.eventsCursor, m.events.len()-1; got != want {
		t.Fatalf("eventsCursor = %d, want %d (should follow the most recent event)", got, want)
	}
}

func TestAppendEventsDoesNotAutoScrollAwayFromManualSelection(t *testing.T) {
	m := newTestModel(nil, 100, 20)

	m.appendEvents(aggregate.Snapshot{SYNEvents: []capture.SYNEvent{{At: testNow}}})
	m.appendEvents(aggregate.Snapshot{SYNEvents: []capture.SYNEvent{{At: testNow.Add(time.Second)}}})
	m.eventsCursor = 0 // user scrolled back to the oldest event

	m.appendEvents(aggregate.Snapshot{SYNEvents: []capture.SYNEvent{{At: testNow.Add(2 * time.Second)}}})

	if m.eventsCursor != 0 {
		t.Errorf("eventsCursor = %d, want 0 (should stay put once the user has scrolled away from the latest event)", m.eventsCursor)
	}
}

func TestEventsWindowStart(t *testing.T) {
	tests := []struct {
		name                        string
		prevStart, cursor, n, limit int
		want                        int
	}{
		{"no scrolling needed fits on screen", 0, 3, 5, 10, 0},
		{"zero limit means unset layout", 0, 3, 5, 0, 0},
		{"cursor already inside the window stays put", 4, 6, 100, 10, 4},
		{"cursor above the window scrolls up to meet it", 4, 2, 100, 10, 2},
		{"cursor below the window scrolls down to meet it", 4, 20, 100, 10, 11},
		{"stale prevStart from a shrunk window is reclamped first", 95, 96, 100, 10, 90},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eventsWindowStart(tt.prevStart, tt.cursor, tt.n, tt.limit); got != tt.want {
				t.Errorf("eventsWindowStart(%d, %d, %d, %d) = %d, want %d",
					tt.prevStart, tt.cursor, tt.n, tt.limit, got, tt.want)
			}
		})
	}
}

// TestMoveEventsCursorScrollsOnlyAtTheViewportEdge exercises the actual
// requirement: scrolling up should move the highlight within an
// already-visible window, only shifting the window itself once the cursor
// would otherwise leave it at the top.
func TestMoveEventsCursorScrollsOnlyAtTheViewportEdge(t *testing.T) {
	m := newTestModel(nil, 100, 20)
	limit := m.eventsRowLines()
	if limit < 2 {
		t.Fatalf("eventsRowLines() = %d, need at least 2 for this test to mean anything", limit)
	}

	// Enough events that the panel is scrolled, with the cursor auto-followed
	// to the bottom-most (most recent) one.
	for i := range limit + 5 {
		m.appendEvents(aggregate.Snapshot{SYNEvents: []capture.SYNEvent{{At: testNow.Add(time.Duration(i) * time.Second)}}})
	}
	n := m.events.len()
	if want := n - 1; m.eventsCursor != want {
		t.Fatalf("eventsCursor = %d, want %d (should auto-follow to the newest event)", m.eventsCursor, want)
	}
	top := m.eventsWindowTop

	// Moving up while still inside the window should move only the cursor,
	// leaving the window's top fixed.
	for i := 0; i < limit-1; i++ {
		m.moveEventsCursor(-1)
		if m.eventsWindowTop != top {
			t.Fatalf("after %d up-moves, eventsWindowTop = %d, want unchanged %d (cursor should still be inside the window)", i+1, m.eventsWindowTop, top)
		}
	}
	if m.eventsCursor != top {
		t.Fatalf("eventsCursor = %d, want %d (should now be pinned at the window's top row)", m.eventsCursor, top)
	}

	// One more up-move walks off the top edge: now the window itself should
	// scroll, by exactly one line, with the cursor still pinned at the top.
	m.moveEventsCursor(-1)
	if want := top - 1; m.eventsWindowTop != want {
		t.Errorf("eventsWindowTop = %d, want %d (should scroll by one line once the cursor hits the top edge)", m.eventsWindowTop, want)
	}
	if m.eventsCursor != m.eventsWindowTop {
		t.Errorf("eventsCursor = %d, want %d (should stay pinned at the top of the window while scrolling)", m.eventsCursor, m.eventsWindowTop)
	}
}

func TestViewEventsHighlightsSelectedRowRegardlessOfFocus(t *testing.T) {
	m := newTestModel(nil, 100, 20)
	m.appendEvents(aggregate.Snapshot{SYNEvents: []capture.SYNEvent{{At: testNow}}})

	m.focus = focusConnections
	unfocused := m.viewEvents()

	m.focus = focusEvents
	focused := m.viewEvents()

	if !slices.Equal(unfocused, focused) {
		t.Errorf("viewEvents() differs by focus:\nunfocused = %v\nfocused   = %v", unfocused, focused)
	}
}

func TestEventKindStrings(t *testing.T) {
	tests := map[eventKind]string{
		eventSYN:       "SYN",
		eventRST:       "RST",
		eventDNSQuery:  "DNS Q",
		eventDNSError:  "DNS ERR",
		eventDNSAnswer: "DNS A",
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
