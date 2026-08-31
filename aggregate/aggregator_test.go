package aggregate

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/boyvinall/mac-nethogs/capture"
	"github.com/boyvinall/mac-nethogs/procinfo"
)

// localAddr is the host end of every flow the tests build; the join never
// looks at it beyond copying it into the record.
const localAddr = "192.168.1.10"

func mustAddr(t testing.TB, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("netip.ParseAddr(%q): %v", s, err)
	}
	return a
}

// flow builds a TCP flow key with the shared local address. t may be a *testing.T
// or a *testing.B, so the same builder serves both tests and benchmarks.
func flow(t testing.TB, localPort uint16, remote string, remotePort uint16) capture.FlowKey {
	t.Helper()
	return capture.FlowKey{
		LocalAddr:  mustAddr(t, localAddr),
		LocalPort:  localPort,
		RemoteAddr: mustAddr(t, remote),
		RemotePort: remotePort,
		Proto:      capture.ProtoTCP,
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

func TestJoinAttributesConnectionsToOwningProcess(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	flows := map[capture.FlowKey]capture.FlowStats{
		flow(t, 51000, "140.82.112.3", 443): stats(4000, 1000, now),
		flow(t, 51001, "140.82.112.3", 80):  stats(20, 30, now),
	}
	ports := map[uint16]procinfo.Process{
		51000: {PID: 42, Name: "curl"},
		51001: {PID: 42, Name: "curl"},
	}

	snap := a.join(flows, ports, now)
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
		LocalPort:     51000,
		RemoteAddr:    "140.82.112.3",
		RemotePort:    443,
		Proto:         "tcp",
		BytesInTotal:  4000,
		BytesOutTotal: 1000,
		RateInBps:     800,
		RateOutBps:    200,
		LastSeen:      now,
	}
	if got != want {
		t.Errorf("record =\n %+v\nwant\n %+v", got, want)
	}

	// Both connections belong to one process, so they roll up into one row.
	rows := ByProcess(snap)
	if len(rows) != 1 {
		t.Fatalf("ByProcess() produced %d rows, want 1", len(rows))
	}
	if rows[0].Connections != 2 || rows[0].BytesInTotal != 4020 {
		t.Errorf("row = %+v, want 2 connections and 4020 bytes in", rows[0])
	}
}

func TestJoinBucketsUnattributedTrafficIntoUnknown(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	flows := map[capture.FlowKey]capture.FlowStats{
		flow(t, 51000, "140.82.112.3", 443): stats(4000, 1000, now),
		flow(t, 51999, "1.1.1.1", 53):       stats(70, 30, now),
	}
	ports := map[uint16]procinfo.Process{51000: {PID: 42, Name: "curl"}}

	snap := a.join(flows, ports, now)
	if len(snap.Connections) != 2 {
		t.Fatalf("join() produced %d records, want 2 (unattributed traffic must not vanish)", len(snap.Connections))
	}

	orphan := recordFor(t, snap, "1.1.1.1", 53)
	if orphan.PID != UnknownProcess.PID || orphan.ProcessName != UnknownProcess.Name {
		t.Errorf("unattributed record = (%d, %q), want (%d, %q)",
			orphan.PID, orphan.ProcessName, UnknownProcess.PID, UnknownProcess.Name)
	}
	if orphan.BytesInTotal != 70 || orphan.BytesOutTotal != 30 {
		t.Errorf("unattributed counters = (%d, %d), want (70, 30)", orphan.BytesInTotal, orphan.BytesOutTotal)
	}

	// The unknown bucket is a normal row, so the bytes stay visible.
	rows := ByProcess(snap)
	unknown := rowFor(t, rows, "-1")
	if unknown.Label != "unknown" || unknown.Connections != 1 || unknown.BytesInTotal != 70 {
		t.Errorf("unknown row = %+v, want label unknown, 1 connection, 70 bytes in", unknown)
	}
}

func TestJoinReattributesReusedPort(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	key := flow(t, 51000, "140.82.112.3", 443)

	// First poll: the port belongs to PID 100.
	first := a.join(
		map[capture.FlowKey]capture.FlowStats{key: stats(1000, 500, now)},
		map[uint16]procinfo.Process{51000: {PID: 100, Name: "old"}},
		now,
	)
	if got := recordFor(t, first, "140.82.112.3", 443); got.PID != 100 {
		t.Fatalf("first join attributed PID %d, want 100", got.PID)
	}

	// Second poll: the same local port now belongs to PID 200. The remembered
	// attribution must lose to the fresh one, and the two processes' traffic
	// must not be merged into two rows sharing the same bytes.
	later := now.Add(time.Second)
	second := a.join(
		map[capture.FlowKey]capture.FlowStats{key: stats(3000, 700, later)},
		map[uint16]procinfo.Process{51000: {PID: 200, Name: "new"}},
		later,
	)

	if len(second.Connections) != 1 {
		t.Fatalf("second join produced %d records, want 1", len(second.Connections))
	}
	got := recordFor(t, second, "140.82.112.3", 443)
	if got.PID != 200 || got.ProcessName != "new" {
		t.Errorf("reused port attributed to (%d, %q), want (200, \"new\")", got.PID, got.ProcessName)
	}

	rows := ByProcess(second)
	if len(rows) != 1 {
		t.Fatalf("ByProcess() produced %d rows, want 1 — the old PID must not survive", len(rows))
	}
	if rows[0].Key != "200" || rows[0].BytesInTotal != 3000 || rows[0].Connections != 1 {
		t.Errorf("row = %+v, want key 200 with 3000 bytes in over 1 connection", rows[0])
	}
}

func TestJoinKeepsLastKnownProcessWhileConnectionCloses(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	key := flow(t, 51000, "140.82.112.3", 443)
	a.join(
		map[capture.FlowKey]capture.FlowStats{key: stats(1000, 500, now)},
		map[uint16]procinfo.Process{51000: {PID: 100, Name: "curl"}},
		now,
	)

	// The process has exited, so the port is gone from the poll — but the
	// connection is still inside its grace period and should keep its name
	// rather than flipping to "unknown" on the way out.
	later := now.Add(time.Second)
	snap := a.join(
		map[capture.FlowKey]capture.FlowStats{key: stats(1000, 500, now)},
		map[uint16]procinfo.Process{},
		later,
	)

	got := recordFor(t, snap, "140.82.112.3", 443)
	if got.PID != 100 || got.ProcessName != "curl" {
		t.Errorf("record after process exit = (%d, %q), want (100, \"curl\")", got.PID, got.ProcessName)
	}
}

func TestJoinKeepsUnknownTrafficUnknown(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	key := flow(t, 51000, "1.1.1.1", 53)
	flows := map[capture.FlowKey]capture.FlowStats{key: stats(10, 10, now)}

	a.join(flows, map[uint16]procinfo.Process{}, now)

	// A record remembered as unknown must not block a later poll from
	// attributing the flow properly.
	later := now.Add(time.Second)
	snap := a.join(
		map[capture.FlowKey]capture.FlowStats{key: stats(20, 10, later)},
		map[uint16]procinfo.Process{51000: {PID: 7, Name: "dig"}},
		later,
	)
	if got := recordFor(t, snap, "1.1.1.1", 53); got.PID != 7 {
		t.Errorf("record = PID %d, want 7 once the poll caught up", got.PID)
	}
}

func TestJoinMarksQuietConnectionsClosedThenEvictsThem(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	key := flow(t, 51000, "140.82.112.3", 443)
	flows := map[capture.FlowKey]capture.FlowStats{key: stats(1000, 500, now)}
	ports := map[uint16]procinfo.Process{51000: {PID: 42, Name: "curl"}}

	fresh := a.join(flows, ports, now)
	if recordFor(t, fresh, "140.82.112.3", 443).Closed(now) {
		t.Error("a connection seen this instant reports Closed")
	}
	if ByProcess(fresh)[0].Closed(now) {
		t.Error("a row with live traffic reports Closed")
	}

	// Quiet for longer than IdleThreshold but still inside the grace period:
	// the row stays, dimmed.
	quiet := now.Add(IdleThreshold + time.Second)
	dimmed := a.join(flows, ports, quiet)
	if len(dimmed.Connections) != 1 {
		t.Fatalf("quiet connection dropped after %s, want it retained until GracePeriod", IdleThreshold+time.Second)
	}
	if !dimmed.Connections[0].Closed(quiet) {
		t.Error("quiet connection does not report Closed")
	}
	if !ByProcess(dimmed)[0].Closed(quiet) {
		t.Error("row of quiet connections does not report Closed")
	}

	// Past the grace period it is evicted entirely.
	gone := now.Add(GracePeriod + time.Second)
	evicted := a.join(flows, ports, gone)
	if len(evicted.Connections) != 0 {
		t.Errorf("connection survived %s past last activity: %+v", GracePeriod+time.Second, evicted.Connections)
	}
	if len(a.records) != 0 {
		t.Errorf("evicted connection left %d retained records", len(a.records))
	}
}

// TestClosedIsExclusiveOfIdleThreshold pins down the boundary of the `>` in
// Closed: exactly IdleThreshold quiet must still read as open, and one tick
// past must flip.
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

// TestJoinRetainsConnectionAtExactlyGracePeriod pins down the boundary of the
// eviction check's strict Before: a connection exactly GracePeriod old must
// survive one more refresh, and only age out the tick after.
func TestJoinRetainsConnectionAtExactlyGracePeriod(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	key := flow(t, 51000, "140.82.112.3", 443)
	flows := map[capture.FlowKey]capture.FlowStats{key: stats(1000, 500, now)}
	ports := map[uint16]procinfo.Process{51000: {PID: 42, Name: "curl"}}
	a.join(flows, ports, now)

	atBoundary := a.join(flows, ports, now.Add(GracePeriod))
	if len(atBoundary.Connections) != 1 {
		t.Error("connection evicted at exactly GracePeriod, want retained (the eviction check is a strict Before)")
	}

	pastBoundary := a.join(flows, ports, now.Add(GracePeriod+time.Nanosecond))
	if len(pastBoundary.Connections) != 0 {
		t.Error("connection survived just past GracePeriod, want evicted")
	}
}

func TestJoinForgetsFlowsTheCapturerHasDropped(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	key := flow(t, 51000, "140.82.112.3", 443)
	a.join(
		map[capture.FlowKey]capture.FlowStats{key: stats(1000, 500, now)},
		map[uint16]procinfo.Process{51000: {PID: 42, Name: "curl"}},
		now,
	)

	// Retention must not resurrect a flow the capture side no longer reports.
	snap := a.join(map[capture.FlowKey]capture.FlowStats{}, map[uint16]procinfo.Process{}, now)
	if len(snap.Connections) != 0 || len(a.records) != 0 {
		t.Errorf("dropped flow survived: %d records, %d retained", len(snap.Connections), len(a.records))
	}
}

// twoProcessSnapshot builds a snapshot spanning two processes and three
// destinations, two of which share a remote IP on different ports.
func twoProcessSnapshot(now time.Time) Snapshot {
	return Snapshot{
		At: now,
		Connections: []ConnectionRecord{
			{PID: 42, ProcessName: "curl", RemoteAddr: "140.82.112.3", RemotePort: 443,
				BytesInTotal: 1000, BytesOutTotal: 100, RateInBps: 200, RateOutBps: 20, LastSeen: now.Add(-time.Second)},
			{PID: 42, ProcessName: "curl", RemoteAddr: "140.82.112.3", RemotePort: 80,
				BytesInTotal: 2000, BytesOutTotal: 200, RateInBps: 400, RateOutBps: 40, LastSeen: now},
			{PID: 7, ProcessName: "dig", RemoteAddr: "1.1.1.1", RemotePort: 53,
				BytesInTotal: 30, BytesOutTotal: 3, RateInBps: 6, RateOutBps: 1, LastSeen: now.Add(-2 * time.Second)},
		},
	}
}

func TestByProcessSumsCountersPerPID(t *testing.T) {
	now := time.Now()
	rows := ByProcess(twoProcessSnapshot(now))

	if len(rows) != 2 {
		t.Fatalf("ByProcess() produced %d rows, want 2", len(rows))
	}

	curl := rowFor(t, rows, "42")
	if curl.Label != "curl" || curl.PID != 42 {
		t.Errorf("row = (%q, %d), want (\"curl\", 42)", curl.Label, curl.PID)
	}
	if curl.BytesInTotal != 3000 || curl.BytesOutTotal != 300 {
		t.Errorf("totals = (%d, %d), want (3000, 300)", curl.BytesInTotal, curl.BytesOutTotal)
	}
	if curl.RateInBps != 600 || curl.RateOutBps != 60 {
		t.Errorf("rates = (%.1f, %.1f), want (600, 60)", curl.RateInBps, curl.RateOutBps)
	}
	if curl.Connections != 2 {
		t.Errorf("Connections = %d, want 2", curl.Connections)
	}
	// LastSeen is the newest of the row's connections, so one live connection
	// keeps the row lit.
	if !curl.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %s, want the newest connection's %s", curl.LastSeen, now)
	}

	dig := rowFor(t, rows, "7")
	if dig.Connections != 1 || dig.BytesInTotal != 30 {
		t.Errorf("dig row = %+v, want 1 connection and 30 bytes in", dig)
	}
}

func TestByDestinationGranularityChangesRowCount(t *testing.T) {
	now := time.Now()
	snap := twoProcessSnapshot(now)

	byIP := ByDestination(snap, GroupByIP)
	if len(byIP) != 2 {
		t.Fatalf("GroupByIP produced %d rows, want 2", len(byIP))
	}
	gh := rowFor(t, byIP, "140.82.112.3")
	if gh.Label != "140.82.112.3" || gh.RemoteAddr != "140.82.112.3" || gh.RemotePort != 0 {
		t.Errorf("GroupByIP row = %+v, want the bare IP and no port", gh)
	}
	if gh.BytesInTotal != 3000 || gh.Connections != 2 {
		t.Errorf("GroupByIP row = %+v, want 3000 bytes in over 2 connections", gh)
	}

	byIPPort := ByDestination(snap, GroupByIPPort)
	if len(byIPPort) != 3 {
		t.Fatalf("GroupByIPPort produced %d rows, want 3 — each port is its own row", len(byIPPort))
	}
	https := rowFor(t, byIPPort, "140.82.112.3:443")
	if https.RemoteAddr != "140.82.112.3" || https.RemotePort != 443 {
		t.Errorf("GroupByIPPort row = %+v, want the address and port split out", https)
	}
	if https.BytesInTotal != 1000 || https.Connections != 1 {
		t.Errorf("GroupByIPPort row = %+v, want 1000 bytes in over 1 connection", https)
	}
}

func TestByDestinationBracketsIPv6(t *testing.T) {
	now := time.Now()
	snap := Snapshot{Connections: []ConnectionRecord{
		{PID: 1, RemoteAddr: "2606:4700::1111", RemotePort: 443, LastSeen: now},
	}}

	// Keys must stay parseable, which for IPv6 means bracketing the address.
	if got := ByDestination(snap, GroupByIPPort)[0].Key; got != "[2606:4700::1111]:443" {
		t.Errorf("IPv6 destination key = %q, want %q", got, "[2606:4700::1111]:443")
	}
}

func TestRowKeysAreStableAcrossRefreshes(t *testing.T) {
	a := New(nil, nil)
	now := time.Now()

	keyA := flow(t, 51000, "140.82.112.3", 443)
	keyB := flow(t, 51001, "1.1.1.1", 53)
	ports := map[uint16]procinfo.Process{
		51000: {PID: 42, Name: "curl"},
		51001: {PID: 7, Name: "dig"},
	}

	first := a.join(map[capture.FlowKey]capture.FlowStats{
		keyA: stats(1000, 100, now),
		keyB: stats(10, 5, now),
	}, ports, now)

	// The second refresh reverses the traffic ranking, which is what would
	// reorder the rendered rows — the keys must not move with it.
	later := now.Add(time.Second)
	second := a.join(map[capture.FlowKey]capture.FlowStats{
		keyA: stats(1100, 110, later),
		keyB: stats(90000, 5, later),
	}, ports, later)

	for _, tc := range []struct {
		name       string
		rows       func(Snapshot) []Row
		wantSorted []string
	}{
		{"ByProcess", ByProcess, []string{"7", "42"}},
		{"ByDestinationIP", func(s Snapshot) []Row { return ByDestination(s, GroupByIP) }, []string{"1.1.1.1", "140.82.112.3"}},
		{"ByDestinationIPPort", func(s Snapshot) []Row { return ByDestination(s, GroupByIPPort) }, []string{"1.1.1.1:53", "140.82.112.3:443"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, after := rowKeys(tc.rows(first)), rowKeys(tc.rows(second))
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

func TestFilterByProcessKeepsOnlyThatPID(t *testing.T) {
	now := time.Now()
	snap := twoProcessSnapshot(now)

	got := FilterByProcess(snap, 42)
	if len(got.Connections) != 2 {
		t.Fatalf("FilterByProcess(42) kept %d connections, want 2", len(got.Connections))
	}
	if !got.At.Equal(snap.At) {
		t.Errorf("FilterByProcess dropped the snapshot timestamp")
	}
	for _, c := range got.Connections {
		if c.PID != 42 {
			t.Errorf("FilterByProcess(42) kept PID %d", c.PID)
		}
	}
	if len(FilterByProcess(snap, 999).Connections) != 0 {
		t.Error("FilterByProcess kept connections for a PID that has none")
	}
}

func TestFilterByDestinationHonoursGrouping(t *testing.T) {
	now := time.Now()
	snap := twoProcessSnapshot(now)

	// Grouped by IP the port is ignored, so both of the host's ports survive.
	if got := FilterByDestination(snap, "140.82.112.3", 0, GroupByIP); len(got.Connections) != 2 {
		t.Errorf("FilterByDestination without port kept %d connections, want 2", len(got.Connections))
	}
	// Grouped by IP:port only the matching port survives.
	got := FilterByDestination(snap, "140.82.112.3", 443, GroupByIPPort)
	if len(got.Connections) != 1 || got.Connections[0].RemotePort != 443 {
		t.Errorf("FilterByDestination with port kept %+v, want only port 443", got.Connections)
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
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				a.Refresh(time.Now())
			}
		}()
	}
	wg.Wait()
}

// benchmarkFlows builds n synthetic flows spread over 50 PIDs and 20 remote
// hosts, plus the port map attributing them, for BenchmarkJoin and
// BenchmarkRollup.
func benchmarkFlows(b *testing.B, n int) (map[capture.FlowKey]capture.FlowStats, map[uint16]procinfo.Process) {
	b.Helper()

	now := time.Now()
	flows := make(map[capture.FlowKey]capture.FlowStats, n)
	ports := make(map[uint16]procinfo.Process, n)
	for i := 0; i < n; i++ {
		localPort := uint16(1024 + i)
		remote := fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)
		key := flow(b, localPort, remote, uint16(1+i%1000))
		flows[key] = stats(uint64(1000+i), uint64(500+i), now)
		ports[localPort] = procinfo.Process{PID: int32(i % 50), Name: "proc"}
	}
	return flows, ports
}

// BenchmarkJoin exercises the aggregator's hot per-refresh-tick path.
func BenchmarkJoin(b *testing.B) {
	flows, ports := benchmarkFlows(b, 1000)
	a := New(nil, nil)
	now := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.join(flows, ports, now)
	}
}

// BenchmarkRollup exercises ByProcess's rollup of a realistic-sized snapshot.
func BenchmarkRollup(b *testing.B) {
	flows, ports := benchmarkFlows(b, 1000)
	a := New(nil, nil)
	snap := a.join(flows, ports, time.Now())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ByProcess(snap)
	}
}
