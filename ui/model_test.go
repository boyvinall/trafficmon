package ui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/boyvinall/mac-nethogs/aggregate"
	"github.com/boyvinall/mac-nethogs/capture"
	"github.com/boyvinall/mac-nethogs/procinfo"
)

func TestViewHeader(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*Model)
		contains []string
		omits    []string
	}{
		{
			name:     "top level process view",
			setup:    func(*Model) {},
			contains: []string{appName, "By Process", "en0", "live"},
			omits:    []string{"PAUSED", "›"},
		},
		{
			name: "destination view names its grouping",
			setup: func(m *Model) {
				m.stack.SetMode(ModeDestination)
				m.grouping = aggregate.GroupByIPPort
			},
			contains: []string{"By Destination (ip:port)"},
		},
		{
			name: "paused capture is flagged",
			setup: func(m *Model) {
				m.paused = true
			},
			contains: []string{"PAUSED"},
			omits:    []string{"live"},
		},
		{
			name: "breadcrumb appears once drilled in",
			setup: func(m *Model) {
				m.stack.Push(Frame{Mode: ModeDestination, Label: "Process: Chrome (pid 4821)"})
			},
			contains: []string{"Process: Chrome (pid 4821)"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestModel(processRows(), 100, 12)
			tc.setup(&m)

			got := m.viewHeader()
			for _, want := range tc.contains {
				if !strings.Contains(got, want) {
					t.Errorf("header %q missing %q", got, want)
				}
			}
			for _, unwanted := range tc.omits {
				if strings.Contains(got, unwanted) {
					t.Errorf("header %q should not contain %q", got, unwanted)
				}
			}
			if w := lipgloss.Width(got); w != 100 {
				t.Errorf("header width = %d, want 100", w)
			}
		})
	}
}

func TestViewFooterIsContextSensitive(t *testing.T) {
	m := newTestModel(processRows(), 100, 12)

	top := m.viewFooter()
	if strings.Contains(top, "back") {
		t.Errorf("top-level footer %q offers esc, which does nothing at depth 0", top)
	}
	for _, want := range []string{"quit", "help", "sort"} {
		if !strings.Contains(top, want) {
			t.Errorf("top-level footer %q missing %q", top, want)
		}
	}

	if !strings.Contains(top, "process/destination") {
		t.Errorf("top-level footer %q should offer tab", top)
	}

	m.stack.Push(Frame{Mode: ModeDestination, Label: "Process: Chrome (pid 4821)"})
	drilled := m.viewFooter()
	if !strings.Contains(drilled, "back") {
		t.Errorf("drilled-in footer %q should offer esc", drilled)
	}

	// Tab only acts at the top level, so below it esc takes its slot rather
	// than the hint line growing a key that does nothing.
	if strings.Contains(drilled, "process/destination") {
		t.Errorf("drilled-in footer %q still offers tab", drilled)
	}
	if len(m.footerKeys()) != len(m.keys.ShortHelp()) {
		t.Errorf("drilled-in footer should swap a hint, not add one")
	}
}

func TestViewHelpOverlay(t *testing.T) {
	m := newTestModel(processRows(), 100, 20)
	m.showHelp = true

	got := m.View()
	if strings.Contains(got, "com.apple.WebKit.Networking") {
		t.Errorf("help overlay should replace the table, got:\n%s", got)
	}

	// Every binding in the full reference should be described, since the
	// overlay is the only place several of them are ever mentioned.
	for _, group := range m.keys.FullHelp() {
		for _, b := range group {
			if !strings.Contains(got, b.Help().Desc) {
				t.Errorf("help overlay missing %q", b.Help().Desc)
			}
		}
	}

	// The header and footer stay put, so the overlay never loses the user.
	if !strings.Contains(got, "By Process") {
		t.Errorf("help overlay dropped the header")
	}
}

func TestViewFitsTerminal(t *testing.T) {
	tests := []struct {
		name          string
		width, height int
		rows          []aggregate.Row
		showHelp      bool
	}{
		{name: "roomy", width: 100, height: 20, rows: processRows()},
		{name: "exactly full", width: 100, height: 8, rows: processRows()},
		{name: "shorter than the rows", width: 100, height: 6, rows: processRows()},
		{name: "no room for anything", width: 100, height: 2, rows: processRows()},
		{name: "narrow", width: 60, height: 12, rows: processRows()},
		// Narrower than the table will shrink to, and narrower than the footer
		// hints can be trimmed to: both have to be clipped by the frame.
		{name: "very narrow", width: 45, height: 12, rows: processRows()},
		{name: "absurdly narrow", width: 20, height: 12, rows: processRows()},
		{name: "destination rows, narrow", width: 45, height: 12, rows: destinationRows()},
		{name: "empty", width: 100, height: 12, rows: nil},
		{name: "help overlay", width: 100, height: 12, rows: processRows(), showHelp: true},
		// The help bubble stops dropping columns before it stops overflowing,
		// so the narrow overlay is checked at several widths rather than one.
		{name: "help overlay, narrow", width: 60, height: 12, rows: processRows(), showHelp: true},
		{name: "help overlay, very narrow", width: 40, height: 12, rows: processRows(), showHelp: true},
		{name: "help overlay, short", width: 100, height: 5, rows: processRows(), showHelp: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestModel(tc.rows, tc.width, tc.height)
			m.showHelp = tc.showHelp

			lines := strings.Split(m.View(), "\n")
			if len(lines) > tc.height {
				t.Errorf("view is %d lines, taller than the %d-line terminal", len(lines), tc.height)
			}
			for i, l := range lines {
				if w := lipgloss.Width(l); w > tc.width {
					t.Errorf("line %d is %d cells wide, wider than the %d-cell terminal: %q", i, w, tc.width, l)
				}
			}
		})
	}
}

func TestViewPinsFooterToTheBottom(t *testing.T) {
	m := newTestModel(processRows(), 100, 20)

	lines := strings.Split(m.View(), "\n")
	if len(lines) != 20 {
		t.Fatalf("view is %d lines, want 20", len(lines))
	}
	if !strings.Contains(lines[19], "quit") {
		t.Errorf("last line %q is not the footer", lines[19])
	}
}

func TestViewEmptyTable(t *testing.T) {
	m := newTestModel(nil, 100, 12)

	if !strings.Contains(m.View(), strings.TrimSpace(emptyMessage)) {
		t.Errorf("an empty table should say so, got:\n%s", m.View())
	}
}

func TestClosedRowsRenderDimmed(t *testing.T) {
	withANSI(t)

	m := newTestModel(processRows(), 100, 12)

	// Keep the cursor off both rows under test: the selected style would
	// otherwise mask the difference this test is looking for.
	m.cursor = -1

	lines := strings.Split(m.View(), "\n")
	live, closed := lines[3], lines[4] // "Google Chrome Helper" and "launchd"

	if !strings.Contains(closed, "launchd") || !strings.Contains(live, "Google Chrome Helper") {
		t.Fatalf("unexpected row order:\n%s", m.View())
	}
	if !m.rows[2].Closed(m.now) || m.rows[1].Closed(m.now) {
		t.Fatalf("fixture is wrong: launchd should be closed and Chrome live")
	}

	if strings.Contains(live, "\x1b[") {
		t.Errorf("a live row should carry no styling, got %q", live)
	}
	if !strings.Contains(closed, "\x1b[2m") {
		t.Errorf("a closed row should render faint, got %q", closed)
	}

	// Dimming must be purely visual: it cannot change the row's width, or
	// closed rows would knock the columns out of alignment.
	if lipgloss.Width(stripANSI(live)) != lipgloss.Width(stripANSI(closed)) {
		t.Errorf("dimming changed the row width")
	}
}

func TestSelectedRowIsHighlighted(t *testing.T) {
	withANSI(t)

	m := newTestModel(processRows(), 100, 12)
	m.cursor = 1

	lines := strings.Split(m.View(), "\n")
	if !strings.Contains(lines[3], "\x1b[7m") {
		t.Errorf("the row under the cursor should be inverted, got %q", lines[3])
	}
	if strings.Contains(lines[2], "\x1b[7m") {
		t.Errorf("only the row under the cursor should be inverted, got %q", lines[2])
	}
}

func TestVisibleWindow(t *testing.T) {
	tests := []struct {
		name             string
		n, cursor, limit int
		wantStart        int
		wantEnd          int
	}{
		{name: "everything fits", n: 5, cursor: 0, limit: 10, wantStart: 0, wantEnd: 5},
		{name: "unbounded", n: 5, cursor: 4, limit: 0, wantStart: 0, wantEnd: 5},
		{name: "cursor at top", n: 20, cursor: 0, limit: 5, wantStart: 0, wantEnd: 5},
		{name: "cursor still on screen", n: 20, cursor: 4, limit: 5, wantStart: 0, wantEnd: 5},
		{name: "cursor scrolled one past", n: 20, cursor: 5, limit: 5, wantStart: 1, wantEnd: 6},
		{name: "cursor at bottom", n: 20, cursor: 19, limit: 5, wantStart: 15, wantEnd: 20},
		{name: "empty", n: 0, cursor: 0, limit: 5, wantStart: 0, wantEnd: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start, end := visibleWindow(tc.n, tc.cursor, tc.limit)
			if start != tc.wantStart || end != tc.wantEnd {
				t.Errorf("visibleWindow(%d, %d, %d) = (%d, %d), want (%d, %d)",
					tc.n, tc.cursor, tc.limit, start, end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestViewScrollsToKeepCursorVisible(t *testing.T) {
	m := newTestModel(processRows(), 100, 7) // room for four rows
	m.cursor = 4

	got := trimRight(m.View())
	if !strings.Contains(got, "unknown") {
		t.Errorf("the cursor row scrolled off screen:\n%s", got)
	}
	if strings.Contains(got, "com.apple") {
		t.Errorf("the first row should have scrolled away:\n%s", got)
	}
}

func TestModeLabel(t *testing.T) {
	tests := []struct {
		name     string
		mode     Mode
		grouping aggregate.Grouping
		want     string
	}{
		{name: "process", mode: ModeProcess, grouping: aggregate.GroupByIP, want: "By Process"},
		{name: "process ignores grouping", mode: ModeProcess, grouping: aggregate.GroupByIPPort, want: "By Process"},
		{name: "destination by ip", mode: ModeDestination, grouping: aggregate.GroupByIP, want: "By Destination (ip)"},
		{name: "destination by ip:port", mode: ModeDestination, grouping: aggregate.GroupByIPPort, want: "By Destination (ip:port)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := modeLabel(tc.mode, tc.grouping); got != tc.want {
				t.Errorf("modeLabel = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestJoinEnds(t *testing.T) {
	tests := []struct {
		name        string
		left, right string
		w           int
		want        string
	}{
		{name: "padded apart", left: "a", right: "b", w: 5, want: "a   b"},
		{name: "minimum gap", left: "ab", right: "cd", w: 5, want: "ab cd"},
		{name: "no room drops the right", left: "ab", right: "cd", w: 4, want: "ab"},
		{name: "left alone overflows", left: "abcdef", right: "gh", w: 4, want: "abcdef"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := joinEnds(tc.left, tc.right, tc.w); got != tc.want {
				t.Errorf("joinEnds = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestViewDestinationMode(t *testing.T) {
	m := newTestModel(destinationRows(), 100, 12)
	m.stack.SetMode(ModeDestination)
	m.grouping = aggregate.GroupByIPPort

	got := m.View()
	for _, want := range []string{"HOST:PORT", "140.82.112.3:443", "[2606:4700:4700::1111]:53", "2.1 MB/s", "128.0 MB"} {
		if !strings.Contains(got, want) {
			t.Errorf("destination view missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "PID") {
		t.Errorf("destination rows carry no PID, so the column must not appear:\n%s", got)
	}
}

func TestUpdateNavigation(t *testing.T) {
	// The live model is in by-process mode, so its rows are the three
	// processes of testSnapshot: indices 0, 1 and 2.
	tests := []struct {
		name   string
		cursor int
		keys   []string
		want   int
	}{
		{name: "down", cursor: 0, keys: []string{"down"}, want: 1},
		{name: "down, vim", cursor: 0, keys: []string{"j"}, want: 1},
		{name: "up", cursor: 2, keys: []string{"up"}, want: 1},
		{name: "up, vim", cursor: 2, keys: []string{"k"}, want: 1},
		{name: "down then up returns", cursor: 1, keys: []string{"down", "up"}, want: 1},

		// Clamping, not wrapping: rows reorder under the cursor as traffic
		// moves, so wrapping would fling the selection to the far end of a
		// table that may have just changed shape.
		{name: "clamps at the top", cursor: 0, keys: []string{"up", "up"}, want: 0},
		{name: "clamps at the bottom", cursor: 2, keys: []string{"down", "down"}, want: 2},

		{name: "page down", cursor: 0, keys: []string{"pgdown"}, want: 2},
		{name: "page up", cursor: 2, keys: []string{"pgup"}, want: 0},
		{name: "page down, vim", cursor: 0, keys: []string{"ctrl+f"}, want: 2},
		{name: "page up, vim", cursor: 2, keys: []string{"ctrl+b"}, want: 0},
		{name: "home", cursor: 2, keys: []string{"home"}, want: 0},
		{name: "end", cursor: 0, keys: []string{"end"}, want: 2},
		{name: "end, vim", cursor: 0, keys: []string{"G"}, want: 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newLiveModel()
			if len(m.rows) != 3 {
				t.Fatalf("fixture has %d rows, want 3", len(m.rows))
			}
			m.cursor = tc.cursor

			m = pressAll(t, m, tc.keys...)
			if m.cursor != tc.want {
				t.Errorf("cursor = %d, want %d", m.cursor, tc.want)
			}
		})
	}
}

func TestUpdateNavigationOnAnEmptyTable(t *testing.T) {
	// Nothing has been captured yet, so every navigation key has to be a
	// harmless no-op rather than leaving the cursor pointing off the end.
	m := newTestModel(nil, 100, 12)

	for _, k := range []string{"up", "down", "pgup", "pgdown", "home", "end"} {
		next, _ := press(t, m, k)
		if next.cursor != 0 {
			t.Errorf("%q on an empty table left the cursor at %d", k, next.cursor)
		}
	}
}

func TestSetRowsHoldsTheCursorOnItsRow(t *testing.T) {
	tests := []struct {
		name   string
		before []string
		cursor int
		after  []string
		want   int
	}{
		{
			name:   "order unchanged",
			before: []string{"a", "b", "c"}, cursor: 1,
			after: []string{"a", "b", "c"}, want: 1,
		},
		{
			// The whole point: the selection follows the row, not the index,
			// or it slides onto whatever row overtook it and enter opens
			// something the user was not pointing at.
			name:   "rows reorder",
			before: []string{"a", "b", "c"}, cursor: 2,
			after: []string{"c", "a", "b"}, want: 0,
		},
		{
			name:   "rows appear above the selection",
			before: []string{"a"}, cursor: 0,
			after: []string{"x", "y", "a"}, want: 2,
		},
		{
			// An evicted row has no new index to find, so the old position is
			// the next best thing: its neighbours are what the user was
			// looking at.
			name:   "selected row is evicted",
			before: []string{"a", "b", "c"}, cursor: 1,
			after: []string{"a", "c"}, want: 1,
		},
		{
			name:   "selected row is evicted from the end",
			before: []string{"a", "b", "c"}, cursor: 2,
			after: []string{"a"}, want: 0,
		},
		{
			name:   "every row is evicted",
			before: []string{"a", "b", "c"}, cursor: 2,
			after: nil, want: 0,
		},
		{
			name:   "rows appear where there were none",
			before: nil, cursor: 0,
			after: []string{"a", "b"}, want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestModel(nil, 100, 12)
			m.setRows(keyRows(tc.before...))
			m.cursor = tc.cursor

			m.setRows(keyRows(tc.after...))
			if m.cursor != tc.want {
				t.Errorf("cursor = %d, want %d", m.cursor, tc.want)
			}
		})
	}
}

func TestCursorFollowsItsRowAcrossARefresh(t *testing.T) {
	m := newLiveModel()

	// sshd is last by rate, which is the default sort.
	m.cursor = len(m.rows) - 1
	if got := m.rows[m.cursor].Label; got != "sshd" {
		t.Fatalf("fixture puts %q last, want sshd", got)
	}

	// Give sshd the most traffic and rebuild, exactly as a tick would: the row
	// moves to the top of the table and the cursor has to move with it.
	snap := testSnapshot()
	snap.Connections[2].RateInBps = 1 << 30
	m.snap = snap
	m.rebuild()

	if m.cursor != 0 || m.rows[m.cursor].Label != "sshd" {
		t.Errorf("cursor = %d (%q), want 0 (sshd)", m.cursor, m.rows[m.cursor].Label)
	}

	// Now let sshd age out entirely. There is no row left to follow, so the
	// cursor stays where it was rather than jumping.
	snap = testSnapshot()
	snap.Connections = snap.Connections[:2]
	m.snap = snap
	m.rebuild()

	if m.cursor != 0 {
		t.Errorf("cursor = %d after the selected row vanished, want 0", m.cursor)
	}
}

func TestUpdateModeToggle(t *testing.T) {
	m := newLiveModel()
	if m.stack.Top().Mode != ModeProcess {
		t.Fatalf("the model should start in by-process mode")
	}

	m, _ = press(t, m, "tab")
	if m.stack.Top().Mode != ModeDestination {
		t.Fatalf("tab did not switch to the by-destination view")
	}

	// The rows have to be rebuilt on the spot, or the header would name one
	// view while the table still showed the other until the next tick.
	if labels := rowLabels(m); strings.Join(labels, ",") != "140.82.112.3,10.0.0.5" {
		t.Errorf("rows = %v, want the destinations", labels)
	}
	if !strings.Contains(m.View(), "By Destination") {
		t.Errorf("header still names the old view:\n%s", m.View())
	}

	m, _ = press(t, m, "tab")
	if m.stack.Top().Mode != ModeProcess {
		t.Errorf("tab did not switch back to the by-process view")
	}
	if labels := rowLabels(m); len(labels) != 3 {
		t.Errorf("rows = %v, want the three processes", labels)
	}
}

func TestUpdateModeToggleIsIgnoredWhileDrilledIn(t *testing.T) {
	// Tab means "show me the other top-level view". Drilled in, the other view
	// of the same scope is what enter offers, and unwinding the drill path on
	// a key that normally does something small would throw away navigation the
	// user did deliberately, so it does nothing at all.
	m := newLiveModel()
	m.stack.Push(Frame{Mode: ModeDestination, Label: "Process: sshd (pid 22)"})
	m.rebuild()

	before := m.View()
	m, _ = press(t, m, "tab")

	if m.stack.Depth() != 1 {
		t.Errorf("tab changed the drill depth to %d, want it left alone", m.stack.Depth())
	}
	if m.stack.Top().Mode != ModeDestination {
		t.Errorf("tab changed the drilled-in view's mode")
	}
	if m.View() != before {
		t.Errorf("tab redrew the drilled-in view")
	}

	// It is not advertised where it does nothing, either.
	if strings.Contains(m.viewFooter(), "process/destination") {
		t.Errorf("the drilled-in footer still offers tab: %q", m.viewFooter())
	}
}

func TestUpdateSortCycling(t *testing.T) {
	// `s` walks every sort key in turn and wraps back to where it started.
	m := newLiveModel()

	want := []SortKey{SortTotal, SortConnections, SortRate}
	for i, k := range want {
		m, _ = press(t, m, "s")
		if m.sort != k {
			t.Fatalf("press %d of s: sort = %s, want %s", i+1, m.sort, k)
		}
	}
}

func TestUpdateRateSortToggle(t *testing.T) {
	tests := []struct {
		name string
		from SortKey
		want SortKey
	}{
		{name: "rate to total", from: SortRate, want: SortTotal},
		{name: "total back to rate", from: SortTotal, want: SortRate},
		// `s` and `r` drive the same sort key, so `r` from the connections
		// sort `s` reached lands on rate rather than doing nothing.
		{name: "connections to rate", from: SortConnections, want: SortRate},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newLiveModel()
			m.sort = tc.from

			m, _ = press(t, m, "r")
			if m.sort != tc.want {
				t.Errorf("sort = %s, want %s", m.sort, tc.want)
			}
		})
	}
}

func TestSortIsVisibleInTheView(t *testing.T) {
	m := newLiveModel()

	// The column carrying the sort is marked, so the row order is explained
	// where the user is already looking.
	if got := m.View(); !strings.Contains(got, sortMarker+"↓ RATE") {
		t.Errorf("the rate columns are not marked as the sort:\n%s", got)
	}

	m, _ = press(t, m, "s")
	got := m.View()
	if !strings.Contains(got, sortMarker+"↓ TOTAL") || strings.Contains(got, sortMarker+"↓ RATE") {
		t.Errorf("the marker did not move to the total columns:\n%s", got)
	}

	// And named in the header, which is the only place left once a narrow
	// terminal has dropped the column it marks.
	if !strings.Contains(got, "sort: total") {
		t.Errorf("the header does not name the sort:\n%s", got)
	}
}

func TestUpdateGroupingToggle(t *testing.T) {
	m := newLiveModel()
	m, _ = press(t, m, "tab")

	if labels := rowLabels(m); strings.Join(labels, ",") != "140.82.112.3,10.0.0.5" {
		t.Fatalf("rows = %v, want one row per remote ip", labels)
	}

	m, _ = press(t, m, "g")
	if m.grouping != aggregate.GroupByIPPort {
		t.Fatalf("g did not switch to the ip:port grouping")
	}
	if labels := rowLabels(m); len(labels) != 3 {
		t.Errorf("rows = %v, want one row per remote ip:port", labels)
	}
	if !strings.Contains(m.View(), "HOST:PORT") {
		t.Errorf("the column title did not follow the grouping:\n%s", m.View())
	}

	m, _ = press(t, m, "g")
	if m.grouping != aggregate.GroupByIP {
		t.Errorf("g did not switch back to the ip grouping")
	}
}

func TestUpdateGroupingToggleIsIgnoredInProcessMode(t *testing.T) {
	// The by-process view has no destinations to regroup, so g does nothing
	// rather than quietly changing a view the user cannot see.
	m := newLiveModel()
	before := m.View()

	m, _ = press(t, m, "g")

	if m.grouping != aggregate.GroupByIP {
		t.Errorf("g changed the grouping from the by-process view")
	}
	if m.View() != before {
		t.Errorf("g redrew the by-process view")
	}
}

func TestUpdatePauseFreezesTheTable(t *testing.T) {
	m := newLiveModel()
	m.cursor = 1

	m, _ = press(t, m, "p")
	if !m.paused {
		t.Fatalf("p did not pause")
	}

	frozen := m.View()
	before := m.now

	// A tick while paused must change nothing at all — not the rows, and not
	// the clock either, since `now` is what decides which rows render as
	// closed and a frozen table would otherwise grey itself out.
	next, cmd := m.Update(tickMsg(before.Add(30 * time.Second)))
	m = next.(Model)

	if cmd == nil {
		t.Errorf("a paused tick must still schedule the next one, or resuming never redraws")
	}
	if !m.now.Equal(before) {
		t.Errorf("now advanced to %v while paused, want %v", m.now, before)
	}
	if m.View() != frozen {
		t.Errorf("the frozen table changed:\n%s\nwant:\n%s", m.View(), frozen)
	}

	// Changing the sort while paused still reorders what is on screen: it
	// re-reads the frozen snapshot rather than asking for a new one.
	m, _ = press(t, m, "s")
	if !strings.Contains(m.View(), "sort: total") || !m.now.Equal(before) {
		t.Errorf("a paused sort change did not redraw, or thawed the clock:\n%s", m.View())
	}

	m, _ = press(t, m, "p")
	if m.paused {
		t.Errorf("p did not resume")
	}
}

func TestUpdateTickRefreshes(t *testing.T) {
	// A real aggregator over a capturer and poller that were never started:
	// both hand out empty snapshots, which is all this needs to prove the tick
	// is wired to the aggregator and to the clock, with no live interface and
	// no root.
	agg := aggregate.New(capture.New(capture.DefaultConfig()), procinfo.NewPoller())

	m := newTestModel(processRows(), 100, 12)
	m.agg = agg

	later := testNow.Add(3 * time.Second)
	next, cmd := m.Update(tickMsg(later))
	m = next.(Model)

	if cmd == nil {
		t.Errorf("the tick must schedule the next one, or the table stops updating")
	}
	if !m.now.Equal(later) {
		t.Errorf("now = %v, want the tick's own timestamp %v", m.now, later)
	}
	if len(m.rows) != 0 {
		t.Errorf("rows = %v, want them rebuilt from the (empty) snapshot", rowLabels(m))
	}
}

func TestUpdateWindowSize(t *testing.T) {
	m := newTestModel(processRows(), 0, 0)

	next, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = next.(Model)

	if m.width != 80 || m.height != 24 {
		t.Errorf("size = %dx%d, want 80x24", m.width, m.height)
	}
}

func TestUpdateHonoursEveryAdvertisedBinding(t *testing.T) {
	// Enter and esc are the drill-down stack, which lands in milestone 6.
	// They are asserted to do nothing rather than skipped, so that wiring them
	// up fails this test and forces the exemption to be deleted with them.
	unimplemented := map[string]bool{"enter": true, "esc": true, "backspace": true}

	for _, binding := range allBindings(t, DefaultKeyMap()) {
		for _, k := range binding.Keys() {
			t.Run(k, func(t *testing.T) {
				// Set the model up so that every binding has something to act
				// on: destinations at the finest grouping give g something to
				// coarsen and leave three rows to move between, and a filter
				// gives `/` something to clear.
				m := newLiveModel()
				m.stack.SetMode(ModeDestination)
				m.grouping = aggregate.GroupByIPPort
				m.filter = "1"
				m.rebuild()
				m.cursor = 1

				if len(m.rows) != 3 {
					t.Fatalf("setup has %d rows, want 3", len(m.rows))
				}

				before := modelState(m, nil)
				next, cmd := press(t, m, k)
				after := modelState(next, cmd)

				if unimplemented[k] {
					if before != after {
						t.Errorf("%q now does something (%s -> %s); wire it up and drop the exemption", k, before, after)
					}
					return
				}
				if before == after {
					t.Errorf("%q is advertised by the help but Update ignores it (%s)", k, before)
				}
			})
		}
	}
}

// modelState is everything a keypress can observably change, rendered so that
// a test can tell "the model reacted" from "the model did not".
func modelState(m Model, cmd tea.Cmd) string {
	return fmt.Sprintf("mode=%d grouping=%d sort=%s cursor=%d depth=%d rows=%v paused=%t help=%t filter=%q quit=%t",
		m.stack.Top().Mode, m.grouping, m.sort, m.cursor, m.stack.Depth(),
		rowLabels(m), m.paused, m.showHelp, m.filter, cmd != nil)
}

// rowLabels is the labels of the rows on screen, in order.
func rowLabels(m Model) []string {
	out := make([]string, len(m.rows))
	for i, r := range m.rows {
		out[i] = r.Label
	}
	return out
}
