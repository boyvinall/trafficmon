package aggregate

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/boyvinall/trafficmon/capture"
	"github.com/boyvinall/trafficmon/procinfo"
)

// localAddr is the host end of every connection the tests build; the join
// never looks at it beyond copying it into the record.
const localAddr = "192.168.1.10"

func mustAddr(t testing.TB, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("netip.ParseAddr(%q): %v", s, err)
	}
	return a
}

// conn builds a TCP connection with the shared local address, as procinfo's
// poller would report it. t may be a *testing.T or a *testing.B, so the same
// builder serves both tests and benchmarks.
func conn(t testing.TB, pid int32, name string, localPort uint16, remote string, remotePort uint16) procinfo.Connection {
	t.Helper()
	return procinfo.Connection{
		PID:         pid,
		ProcessName: name,
		LocalAddr:   mustAddr(t, localAddr),
		LocalPort:   localPort,
		RemoteAddr:  mustAddr(t, remote),
		RemotePort:  remotePort,
		Proto:       "tcp",
	}
}

// flowFor builds the capture.FlowKey that joins onto c.
func flowFor(c procinfo.Connection) capture.FlowKey {
	return capture.FlowKey{
		LocalAddr:  c.LocalAddr,
		LocalPort:  c.LocalPort,
		RemoteAddr: c.RemoteAddr,
		RemotePort: c.RemotePort,
		Proto:      protoFromString(c.Proto),
	}
}

func stats(in, out uint64, lastSeen time.Time) capture.FlowStats {
	return capture.FlowStats{
		BytesIn:    in,
		BytesOut:   out,
		RateInBps:  float64(in) / 5,
		RateOutBps: float64(out) / 5,
		LastSeen:   lastSeen,
	}
}

// recordFor finds the record for one remote endpoint, failing if it is absent.
func recordFor(t *testing.T, snap Snapshot, remote string, remotePort uint16) ConnectionRecord {
	t.Helper()
	for _, c := range snap.Connections {
		if c.RemoteAddr == remote && c.RemotePort == remotePort {
			return c
		}
	}
	t.Fatalf("no record for %s:%d in %+v", remote, remotePort, snap.Connections)
	return ConnectionRecord{}
}

func rowFor(t *testing.T, rows []Row, key string) Row {
	t.Helper()
	for _, r := range rows {
		if r.Key == key {
			return r
		}
	}
	t.Fatalf("no row keyed %q in %+v", key, rows)
	return Row{}
}

func rowKeys(rows []Row) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Key)
	}
	return out
}

func TestJoinMergesTrafficOntoOpenConnections(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	c1 := conn(t, 42, "curl", 51000, "140.82.112.3", 443)
	c2 := conn(t, 42, "curl", 51001, "140.82.112.3", 80)
	flows := map[capture.FlowKey]capture.FlowStats{
		flowFor(c1): stats(4000, 1000, now),
		flowFor(c2): stats(20, 30, now),
	}

	snap := a.join([]procinfo.Connection{c1, c2}, flows, now)
	if len(snap.Connections) != 2 {
		t.Fatalf("join() produced %d records, want 2", len(snap.Connections))
	}
	if !snap.At.Equal(now) {
		t.Errorf("snap.At = %s, want %s", snap.At, now)
	}

	got := recordFor(t, snap, "140.82.112.3", 443)
	want := ConnectionRecord{
		PID:           42,
		ProcessName:   "curl",
		LocalAddr:     localAddr,
		LocalPort:     51000,
		RemoteAddr:    "140.82.112.3",
		RemotePort:    443,
		Proto:         "tcp",
		BytesInTotal:  4000,
		BytesOutTotal: 1000,
		RateInBps:     800,
		RateOutBps:    200,
		LastSeen:      now,
		LastPolled:    now,
		FirstSeen:     now,
	}
	if got != want {
		t.Errorf("record =\n %+v\nwant\n %+v", got, want)
	}

	// The two connections belong to one process but talk to two different
	// destinations, so grouping by PID gives each its own row.
	rows := Rows(snap, GroupByPID)
	if len(rows) != 2 {
		t.Fatalf("Rows(GroupByPID) produced %d rows, want 2", len(rows))
	}
}

func TestJoinPropagatesHostnameFromFlowStats(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	c := conn(t, 42, "curl", 51000, "140.82.112.3", 443)
	st := stats(4000, 1000, now)
	st.Hostname = "example.com"

	snap := a.join([]procinfo.Connection{c}, map[capture.FlowKey]capture.FlowStats{flowFor(c): st}, now)
	got := recordFor(t, snap, "140.82.112.3", 443)
	if got.Hostname != "example.com" {
		t.Errorf("record.Hostname = %q, want %q", got.Hostname, "example.com")
	}

	rows := Rows(snap, GroupNone)
	if len(rows) != 1 || rows[0].Hostname != "example.com" {
		t.Errorf("Rows(GroupNone) = %+v, want a single row with Hostname %q", rows, "example.com")
	}
}

func TestJoinPropagatesHostnameForICMPFlow(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	icmpKey := capture.FlowKey{
		LocalAddr: mustAddr(t, localAddr), RemoteAddr: mustAddr(t, "1.1.1.1"), Proto: capture.ProtoICMP,
	}
	st := stats(100, 0, now)
	st.Hostname = "one.one.one.one"

	snap := a.join(nil, map[capture.FlowKey]capture.FlowStats{icmpKey: st}, now)
	got := recordFor(t, snap, "1.1.1.1", 0)
	if got.Hostname != "one.one.one.one" {
		t.Errorf("icmp record.Hostname = %q, want %q", got.Hostname, "one.one.one.one")
	}
}

func TestJoinShowsAConnectionWithNoTrafficYet(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	c := conn(t, 42, "ssh", 51000, "140.82.112.3", 22)

	// No capture data at all: the connection must still produce a row, with
	// zero bytes and no LastSeen, and must not read as Closed.
	snap := a.join([]procinfo.Connection{c}, map[capture.FlowKey]capture.FlowStats{}, now)
	if len(snap.Connections) != 1 {
		t.Fatalf("join() produced %d records, want 1", len(snap.Connections))
	}
	got := recordFor(t, snap, "140.82.112.3", 22)
	if got.BytesInTotal != 0 || got.BytesOutTotal != 0 || !got.LastSeen.IsZero() {
		t.Errorf("record with no capture data = %+v, want zero traffic and zero LastSeen", got)
	}
	if got.Closed(now) {
		t.Error("a freshly polled connection with no traffic yet reports Closed")
	}
	if !got.FirstSeen.Equal(now) {
		t.Errorf("FirstSeen = %s, want %s (stamped on first sight)", got.FirstSeen, now)
	}
}

func TestJoinKeepsVanishedConnectionWithinGracePeriod(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	c := conn(t, 42, "dig", 51000, "1.1.1.1", 53)
	a.join([]procinfo.Connection{c}, map[capture.FlowKey]capture.FlowStats{}, now)

	// The socket is gone from the next poll (the connection closed), but
	// within GracePeriod it must stay on screen, dimmed.
	later := now.Add(time.Second)
	snap := a.join(nil, map[capture.FlowKey]capture.FlowStats{}, later)
	if len(snap.Connections) != 1 {
		t.Fatalf("join() produced %d records, want 1 (still within grace period)", len(snap.Connections))
	}
	got := recordFor(t, snap, "1.1.1.1", 53)
	if !got.Vanished {
		t.Error("connection missing from the poll does not report Vanished")
	}
	if !got.Closed(later) {
		t.Error("a vanished connection does not report Closed")
	}
	if got.PID != 42 || got.ProcessName != "dig" {
		t.Errorf("vanished record = (%d, %q), want (42, \"dig\") retained from the last poll", got.PID, got.ProcessName)
	}
	if !got.FirstSeen.Equal(now) {
		t.Errorf("vanished record FirstSeen = %s, want %s (carried forward from the first poll, not reset)", got.FirstSeen, now)
	}

	// Past the grace period it is dropped for good.
	gone := now.Add(GracePeriod + time.Nanosecond)
	evicted := a.join(nil, map[capture.FlowKey]capture.FlowStats{}, gone)
	if len(evicted.Connections) != 0 {
		t.Errorf("vanished connection survived past GracePeriod: %+v", evicted.Connections)
	}
	if len(a.records) != 0 {
		t.Errorf("evicted connection left %d retained records", len(a.records))
	}
}

func TestJoinShowsUnattributedICMPAndARPFlows(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	icmpKey := capture.FlowKey{
		LocalAddr: mustAddr(t, localAddr), RemoteAddr: mustAddr(t, "1.1.1.1"), Proto: capture.ProtoICMP,
	}
	arpKey := capture.FlowKey{
		LocalAddr: mustAddr(t, localAddr), RemoteAddr: mustAddr(t, "192.168.1.1"), Proto: capture.ProtoARP,
	}
	flows := map[capture.FlowKey]capture.FlowStats{
		icmpKey: stats(100, 0, now),
		arpKey:  stats(0, 28, now),
	}

	// No procinfo connections at all: neither flow has a socket, so nothing
	// but the capture side attributes them.
	snap := a.join(nil, flows, now)
	if len(snap.Connections) != 2 {
		t.Fatalf("join() produced %d records, want 2 (icmp + arp)", len(snap.Connections))
	}

	icmp := recordFor(t, snap, "1.1.1.1", 0)
	if icmp.PID != 0 || icmp.ProcessName != unattributedProcessLabel || icmp.Proto != "icmp" {
		t.Errorf("icmp record = %+v, want PID 0, ProcessName %q, Proto \"icmp\"", icmp, unattributedProcessLabel)
	}
	if icmp.BytesInTotal != 100 {
		t.Errorf("icmp record BytesInTotal = %d, want 100", icmp.BytesInTotal)
	}

	arp := recordFor(t, snap, "192.168.1.1", 0)
	if arp.PID != 0 || arp.ProcessName != unattributedProcessLabel || arp.Proto != "arp" {
		t.Errorf("arp record = %+v, want PID 0, ProcessName %q, Proto \"arp\"", arp, unattributedProcessLabel)
	}

	// Once the flow is gone from capture (evicted), the grace-period
	// carry-forward already generic to every protocol picks it up: it stays
	// dimmed for one more tick, then drops entirely.
	later := now.Add(time.Second)
	still := a.join(nil, map[capture.FlowKey]capture.FlowStats{}, later)
	stillICMP := recordFor(t, still, "1.1.1.1", 0)
	if !stillICMP.Vanished {
		t.Error("icmp flow missing from capture does not report Vanished")
	}

	gone := now.Add(GracePeriod + time.Nanosecond)
	evicted := a.join(nil, map[capture.FlowKey]capture.FlowStats{}, gone)
	if len(evicted.Connections) != 0 {
		t.Errorf("unattributed flows survived past GracePeriod: %+v", evicted.Connections)
	}
}

func TestJoinRetainsVanishedConnectionAtExactlyGracePeriod(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	c := conn(t, 42, "curl", 51000, "140.82.112.3", 443)
	a.join([]procinfo.Connection{c}, map[capture.FlowKey]capture.FlowStats{}, now)

	atBoundary := a.join(nil, map[capture.FlowKey]capture.FlowStats{}, now.Add(GracePeriod))
	if len(atBoundary.Connections) != 1 {
		t.Error("vanished connection evicted at exactly GracePeriod, want retained (the eviction check is a strict Before)")
	}
	if got := recordFor(t, atBoundary, "140.82.112.3", 443); !got.FirstSeen.Equal(now) {
		t.Errorf("vanished record FirstSeen = %s, want %s (carried forward, not reset)", got.FirstSeen, now)
	}

	pastBoundary := a.join(nil, map[capture.FlowKey]capture.FlowStats{}, now.Add(GracePeriod+time.Nanosecond))
	if len(pastBoundary.Connections) != 0 {
		t.Error("vanished connection survived just past GracePeriod, want evicted")
	}
}

func TestJoinReplacesPreviousBandwidthOnceReattributed(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	c := conn(t, 100, "old", 51000, "140.82.112.3", 443)
	first := a.join([]procinfo.Connection{c}, map[capture.FlowKey]capture.FlowStats{flowFor(c): stats(1000, 500, now)}, now)
	if got := recordFor(t, first, "140.82.112.3", 443); got.PID != 100 {
		t.Fatalf("first join reported PID %d, want 100", got.PID)
	}

	// The old connection has closed and a different process now holds the
	// same local port, connected elsewhere: it is a distinct connection, not
	// a continuation of the first, and must not inherit its bandwidth. The
	// old one still shows up once more, vanished, within its own grace
	// period.
	later := now.Add(time.Second)
	c2 := conn(t, 200, "new", 51000, "8.8.8.8", 443)
	second := a.join([]procinfo.Connection{c2}, map[capture.FlowKey]capture.FlowStats{flowFor(c2): stats(3000, 700, later)}, later)

	if len(second.Connections) != 2 {
		t.Fatalf("second join produced %d records, want 2 (the new connection, plus the old one vanished)", len(second.Connections))
	}
	got := recordFor(t, second, "8.8.8.8", 443)
	if got.PID != 200 || got.ProcessName != "new" || got.BytesInTotal != 3000 {
		t.Errorf("reused port record = %+v, want PID 200 \"new\" with 3000 bytes in", got)
	}
	old := recordFor(t, second, "140.82.112.3", 443)
	if !old.Vanished || old.PID != 100 {
		t.Errorf("old connection = %+v, want PID 100 and Vanished", old)
	}
}

func TestJoinMarksQuietUDPConnectionsClosedThenEvictsThem(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	c := procinfo.Connection{
		PID: 42, ProcessName: "curl",
		LocalAddr: mustAddr(t, localAddr), LocalPort: 51000,
		RemoteAddr: mustAddr(t, "140.82.112.3"), RemotePort: 443,
		Proto: "udp",
	}
	flows := map[capture.FlowKey]capture.FlowStats{flowFor(c): stats(1000, 500, now)}

	fresh := a.join([]procinfo.Connection{c}, flows, now)
	if recordFor(t, fresh, "140.82.112.3", 443).Closed(now) {
		t.Error("a UDP connection seen this instant reports Closed")
	}
	if Rows(fresh, GroupNone)[0].Closed(now) {
		t.Error("a row with live traffic reports Closed")
	}

	// Quiet for longer than IdleThreshold, but the socket is still being
	// polled, so it stays — dimmed, not vanished.
	quiet := now.Add(IdleThreshold + time.Second)
	dimmed := a.join([]procinfo.Connection{c}, flows, quiet)
	if len(dimmed.Connections) != 1 {
		t.Fatalf("quiet connection dropped, want it retained (still open, just idle)")
	}
	if !dimmed.Connections[0].Closed(quiet) {
		t.Error("quiet UDP connection does not report Closed")
	}
	if dimmed.Connections[0].Vanished {
		t.Error("a still-open, merely idle connection reports Vanished")
	}

	// Once it actually vanishes from the poll, it is retained (dimmed) only
	// for GracePeriod.
	gone := quiet.Add(GracePeriod + time.Nanosecond)
	evicted := a.join(nil, map[capture.FlowKey]capture.FlowStats{}, gone)
	if len(evicted.Connections) != 0 {
		t.Errorf("connection survived %s past vanishing: %+v", GracePeriod+time.Nanosecond, evicted.Connections)
	}
}

// TestClosedIsExclusiveOfIdleThreshold pins down the boundary of the `>` in
// Closed: exactly IdleThreshold quiet must still read as open, and one tick
// past must flip. Both use a no-state (UDP) record, since a TCP record's
// Closed reads its State instead.
func TestClosedIsExclusiveOfIdleThreshold(t *testing.T) {
	lastSeen := time.Now()
	record := ConnectionRecord{LastSeen: lastSeen}
	row := Row{LastSeen: lastSeen}

	atThreshold := lastSeen.Add(IdleThreshold)
	if record.Closed(atThreshold) {
		t.Error("ConnectionRecord.Closed() at exactly IdleThreshold reports closed, want open (Closed uses >, not >=)")
	}
	if row.Closed(atThreshold) {
		t.Error("Row.Closed() at exactly IdleThreshold reports closed, want open (Closed uses >, not >=)")
	}

	pastThreshold := lastSeen.Add(IdleThreshold + time.Nanosecond)
	if !record.Closed(pastThreshold) {
		t.Error("ConnectionRecord.Closed() just past IdleThreshold reports open, want closed")
	}
	if !row.Closed(pastThreshold) {
		t.Error("Row.Closed() just past IdleThreshold reports open, want closed")
	}
}

// TestClosedReadsTCPState covers every branch of closingTCPState via
// ConnectionRecord.Closed, independent of traffic or vanishing.
func TestClosedReadsTCPState(t *testing.T) {
	now := time.Now()
	tests := []struct {
		state string
		want  bool
	}{
		{"ESTABLISHED", false},
		{"LISTEN", false},
		{"SYN_SENT", false},
		{"SYN_RCVD", false},
		{"CLOSE_WAIT", true},
		{"LAST_ACK", true},
		{"CLOSING", true},
		{"TIME_WAIT", true},
		{"FIN_WAIT_1", true},
		{"FIN_WAIT_2", true},
		{"CLOSED", true},
	}
	for _, tc := range tests {
		t.Run(tc.state, func(t *testing.T) {
			r := ConnectionRecord{State: tc.state, LastPolled: now}
			if got := r.Closed(now); got != tc.want {
				t.Errorf("Closed() with State %q = %v, want %v", tc.state, got, tc.want)
			}
		})
	}
}

func TestJoinForgetsConnectionsCaptureHasDropped(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	c := conn(t, 42, "curl", 51000, "140.82.112.3", 443)
	a.join([]procinfo.Connection{c}, map[capture.FlowKey]capture.FlowStats{flowFor(c): stats(1000, 500, now)}, now)

	// The socket itself is gone and grace has elapsed: nothing left to show,
	// and nothing left retained.
	snap := a.join(nil, map[capture.FlowKey]capture.FlowStats{}, now.Add(GracePeriod+time.Nanosecond))
	if len(snap.Connections) != 0 || len(a.records) != 0 {
		t.Errorf("connection survived past grace: %d records, %d retained", len(snap.Connections), len(a.records))
	}
}

// multiConnSnapshot builds a snapshot spanning two processes and three
// destinations, two of which share a remote IP on different ports.
func multiConnSnapshot(now time.Time) Snapshot {
	return Snapshot{
		At: now,
		Connections: []ConnectionRecord{
			{PID: 42, ProcessName: "curl", LocalAddr: localAddr, LocalPort: 51000, RemoteAddr: "140.82.112.3", RemotePort: 443, Proto: "tcp",
				BytesInTotal: 1000, BytesOutTotal: 100, RateInBps: 200, RateOutBps: 20, LastSeen: now.Add(-time.Second), FirstSeen: now.Add(-time.Hour)},
			{PID: 42, ProcessName: "curl", LocalAddr: localAddr, LocalPort: 51001, RemoteAddr: "140.82.112.3", RemotePort: 80, Proto: "tcp",
				BytesInTotal: 2000, BytesOutTotal: 200, RateInBps: 400, RateOutBps: 40, LastSeen: now, FirstSeen: now.Add(-2 * time.Hour)},
			{PID: 7, ProcessName: "dig", LocalAddr: localAddr, LocalPort: 51002, RemoteAddr: "1.1.1.1", RemotePort: 53, Proto: "udp",
				BytesInTotal: 30, BytesOutTotal: 3, RateInBps: 6, RateOutBps: 1, LastSeen: now.Add(-2 * time.Second), FirstSeen: now.Add(-3 * time.Hour)},
		},
	}
}

func TestRowsUngroupedIsOnePerConnection(t *testing.T) {
	now := time.Now()
	rows := Rows(multiConnSnapshot(now), GroupNone)

	if len(rows) != 3 {
		t.Fatalf("Rows(GroupNone) produced %d rows, want 3", len(rows))
	}
	for _, r := range rows {
		if r.Connections != 1 {
			t.Errorf("row %+v has Connections = %d, want 1", r, r.Connections)
		}
		if r.RemoteAddr == "" || r.LocalAddr == "" {
			t.Errorf("row %+v missing local/remote address", r)
		}
	}
}

func TestRowsByPIDSumsCountersPerProcess(t *testing.T) {
	now := time.Now()
	rows := Rows(multiConnSnapshot(now), GroupByPID)

	// curl's two connections go to different remote ports, so grouping by
	// PID and remote endpoint keeps them apart; only dig's lone connection
	// gets a row of its own too, for 3 rows total.
	if len(rows) != 3 {
		t.Fatalf("Rows(GroupByPID) produced %d rows, want 3", len(rows))
	}

	curl443 := rowFor(t, rows, "42|140.82.112.3|443")
	if curl443.Label != "curl" || curl443.PID != 42 || curl443.RemoteAddr != "140.82.112.3" || curl443.RemotePort != 443 {
		t.Errorf("row = %+v, want curl/42 to 140.82.112.3:443", curl443)
	}
	if curl443.BytesInTotal != 1000 || curl443.BytesOutTotal != 100 || curl443.Connections != 1 {
		t.Errorf("row = %+v, want 1000/100 bytes over 1 connection", curl443)
	}
	if !curl443.FirstSeen.Equal(now.Add(-time.Hour)) {
		t.Errorf("row.FirstSeen = %s, want %s (its lone connection's FirstSeen)", curl443.FirstSeen, now.Add(-time.Hour))
	}

	curl80 := rowFor(t, rows, "42|140.82.112.3|80")
	if curl80.BytesInTotal != 2000 || curl80.BytesOutTotal != 200 || curl80.Connections != 1 {
		t.Errorf("row = %+v, want 2000/200 bytes over 1 connection", curl80)
	}
	// A grouped row can't state a single State, so it is left blank even
	// though RemoteAddr and RemotePort now carry over exactly.
	if curl80.State != "" {
		t.Errorf("GroupByPID row = %+v, want State left blank", curl80)
	}

	dig := rowFor(t, rows, "7|1.1.1.1|53")
	if dig.Connections != 1 || dig.BytesInTotal != 30 {
		t.Errorf("dig row = %+v, want 1 connection and 30 bytes in", dig)
	}
}

func TestRowsByPIDMergesConnectionsToTheSameDestination(t *testing.T) {
	now := time.Now()
	snap := Snapshot{Connections: []ConnectionRecord{
		{PID: 42, ProcessName: "curl", RemoteAddr: "140.82.112.3", RemotePort: 443, BytesInTotal: 1000, LastSeen: now, Hostname: "first.example.com", FirstSeen: now.Add(-time.Hour)},
		{PID: 42, ProcessName: "curl", RemoteAddr: "140.82.112.3", RemotePort: 443, BytesInTotal: 2000, LastSeen: now, Hostname: "second.example.com", FirstSeen: now.Add(-2 * time.Hour)},
	}}

	rows := Rows(snap, GroupByPID)
	if len(rows) != 1 {
		t.Fatalf("Rows(GroupByPID) produced %d rows, want 1 (same PID, same destination)", len(rows))
	}
	if got := rows[0]; got.Connections != 2 || got.BytesInTotal != 3000 {
		t.Errorf("row = %+v, want 2 connections and 3000 bytes in", got)
	}
	// Hostname has no single answer once connections are rolled together:
	// the row keeps whichever one rollup saw first, same as LocalAddr does.
	if got := rows[0].Hostname; got != "first.example.com" {
		t.Errorf("row.Hostname = %q, want %q (first-seen representative value)", got, "first.example.com")
	}
	// FirstSeen, unlike Hostname, does have a single right answer once
	// connections are rolled together: the earliest of them.
	if got := rows[0].FirstSeen; !got.Equal(now.Add(-2 * time.Hour)) {
		t.Errorf("row.FirstSeen = %s, want %s (the minimum across the group)", got, now.Add(-2*time.Hour))
	}
}

func TestRowsByProcessNameGroupsAcrossPIDs(t *testing.T) {
	now := time.Now()
	snap := Snapshot{Connections: []ConnectionRecord{
		{PID: 100, ProcessName: "chrome", RemoteAddr: "1.1.1.1", RemotePort: 443, BytesInTotal: 10, LastSeen: now, FirstSeen: now.Add(-2 * time.Hour)},
		{PID: 200, ProcessName: "chrome", RemoteAddr: "1.1.1.1", RemotePort: 443, BytesInTotal: 20, LastSeen: now, FirstSeen: now.Add(-time.Hour)},
	}}

	rows := Rows(snap, GroupByProcessName)
	if len(rows) != 1 {
		t.Fatalf("Rows(GroupByProcessName) produced %d rows, want 1 (two PIDs, same destination)", len(rows))
	}
	got := rows[0]
	if got.Label != "chrome" || got.PID != 0 || got.LocalAddr != "" {
		t.Errorf("row = %+v, want label \"chrome\" with PID and LocalAddr left blank (spans two PIDs)", got)
	}
	if got.RemoteAddr != "1.1.1.1" || got.RemotePort != 443 {
		t.Errorf("row = %+v, want the shared remote endpoint carried over", got)
	}
	if got.BytesInTotal != 30 || got.Connections != 2 {
		t.Errorf("row = %+v, want 30 bytes in over 2 connections", got)
	}
	if !got.FirstSeen.Equal(now.Add(-2 * time.Hour)) {
		t.Errorf("row.FirstSeen = %s, want %s (the minimum across the two PIDs)", got.FirstSeen, now.Add(-2*time.Hour))
	}
}

// TestRowsByProcessNameSplitsByDestination shows the other half of grouping
// by process name: two PIDs sharing a name but talking to different
// destinations get one row each.
func TestRowsByProcessNameSplitsByDestination(t *testing.T) {
	now := time.Now()
	snap := Snapshot{Connections: []ConnectionRecord{
		{PID: 100, ProcessName: "chrome", RemoteAddr: "1.1.1.1", RemotePort: 443, BytesInTotal: 10, LastSeen: now},
		{PID: 200, ProcessName: "chrome", RemoteAddr: "2.2.2.2", RemotePort: 443, BytesInTotal: 20, LastSeen: now},
	}}

	rows := Rows(snap, GroupByProcessName)
	if len(rows) != 2 {
		t.Fatalf("Rows(GroupByProcessName) produced %d rows, want 2 (different destinations)", len(rows))
	}
}

func TestGroupingCyclesThroughAllThreeModes(t *testing.T) {
	seen := map[Grouping]bool{}
	g := GroupNone
	for range 3 {
		seen[g] = true
		g = g.Next()
	}
	if g != GroupNone {
		t.Errorf("Grouping.Next() after 3 steps = %v, want back at GroupNone", g)
	}
	if !seen[GroupNone] || !seen[GroupByPID] || !seen[GroupByProcessName] {
		t.Errorf("cycle visited %v, want all three groupings", seen)
	}
}

func TestRowKeysAreStableAcrossRefreshes(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	cA := conn(t, 42, "curl", 51000, "140.82.112.3", 443)
	cB := conn(t, 7, "dig", 51001, "1.1.1.1", 53)

	first := a.join([]procinfo.Connection{cA, cB}, map[capture.FlowKey]capture.FlowStats{
		flowFor(cA): stats(1000, 100, now),
		flowFor(cB): stats(10, 5, now),
	}, now)

	// The second refresh reverses the traffic ranking, which is what would
	// reorder the rendered rows — the keys must not move with it.
	later := now.Add(time.Second)
	second := a.join([]procinfo.Connection{cA, cB}, map[capture.FlowKey]capture.FlowStats{
		flowFor(cA): stats(1100, 110, later),
		flowFor(cB): stats(90000, 5, later),
	}, later)

	for _, tc := range []struct {
		name       string
		g          Grouping
		wantSorted []string
	}{
		{"GroupByPID", GroupByPID, []string{"7|1.1.1.1|53", "42|140.82.112.3|443"}},
		{"GroupByProcessName", GroupByProcessName, []string{"curl|140.82.112.3|443", "dig|1.1.1.1|53"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, after := rowKeys(Rows(first, tc.g)), rowKeys(Rows(second, tc.g))
			if len(before) != len(after) {
				t.Fatalf("row count changed: %v then %v", before, after)
			}
			for i := range before {
				if before[i] != after[i] {
					t.Errorf("key at index %d changed: %q then %q", i, before[i], after[i])
				}
			}
		})
	}
}

func TestRefreshWiresBothSources(t *testing.T) {
	// Neither source needs root as long as nothing is captured or polled, so
	// this exercises the wiring — including the capture-side eviction — that
	// join() itself never touches.
	a := New(capture.New(capture.DefaultConfig()), procinfo.NewPoller())

	snap := a.Refresh(time.Now())
	if len(snap.Connections) != 0 {
		t.Errorf("Refresh() on idle sources produced %d records, want 0", len(snap.Connections))
	}
}

// TestAggregatorRefreshIsSafeForConcurrentUse drives Refresh from many
// goroutines against one Aggregator, to prove the mutex guarding records is
// sufficient. Run with -race to catch anything it misses.
func TestAggregatorRefreshIsSafeForConcurrentUse(t *testing.T) {
	a := New(capture.New(capture.DefaultConfig()), procinfo.NewPoller())

	const goroutines = 8
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range iterations {
				a.Refresh(time.Now())
			}
		}()
	}
	wg.Wait()
}

// benchmarkConns builds n synthetic open connections spread over 50 PIDs and
// 20 remote hosts, plus the flow stats for each, for BenchmarkJoin and
// BenchmarkRollup.
func benchmarkConns(b *testing.B, n int) ([]procinfo.Connection, map[capture.FlowKey]capture.FlowStats) {
	b.Helper()

	now := time.Now()
	conns := make([]procinfo.Connection, 0, n)
	flows := make(map[capture.FlowKey]capture.FlowStats, n)
	for i := range n {
		localPort := uint16(1024 + i)
		remote := fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)
		c := conn(b, int32(i%50), "proc", localPort, remote, uint16(1+i%1000))
		conns = append(conns, c)
		flows[flowFor(c)] = stats(uint64(1000+i), uint64(500+i), now)
	}
	return conns, flows
}

// BenchmarkJoin exercises the aggregator's hot per-refresh-tick path.
func BenchmarkJoin(b *testing.B) {
	conns, flows := benchmarkConns(b, 1000)
	a := New(nil, nil)
	now := time.Now()

	b.ResetTimer()
	for range b.N {
		a.join(conns, flows, now)
	}
}

// BenchmarkRollup exercises Rows' rollup of a realistic-sized snapshot.
func BenchmarkRollup(b *testing.B) {
	conns, flows := benchmarkConns(b, 1000)
	a := New(nil, nil)
	snap := a.join(conns, flows, time.Now())

	b.ResetTimer()
	for range b.N {
		Rows(snap, GroupByPID)
	}
}
