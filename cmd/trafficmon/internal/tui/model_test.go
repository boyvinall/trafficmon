package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/boyvinall/trafficmon/aggregate"
	"github.com/boyvinall/trafficmon/capture"
	"github.com/boyvinall/trafficmon/dpi"
	"github.com/boyvinall/trafficmon/procinfo"
)

func TestViewHeader(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*Model)
		contains []string
		omits    []string
	}{
		{
			name:     "ungrouped by default",
			setup:    func(*Model) {},
			contains: []string{appName, "Ungrouped", "en0", "live"},
			omits:    []string{"PAUSED"},
		},
		{
			name: "grouping names itself",
			setup: func(m *Model) {
				m.grouping = aggregate.GroupByProcessName
			},
			contains: []string{"By Process"},
		},
		{
			name: "paused capture is flagged",
			setup: func(m *Model) {
				m.paused = true
			},
			contains: []string{"PAUSED"},
			omits:    []string{"live"},
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

func TestViewFooterOffersGroupingAndSort(t *testing.T) {
	m := newTestModel(processRows(), 100, 12)

	got := m.viewFooter()
	for _, want := range []string{"quit", "help", "sort", "grouping"} {
		if !strings.Contains(got, want) {
			t.Errorf("footer %q missing %q", got, want)
		}
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
	if !strings.Contains(got, "Ungrouped") {
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
		{name: "ungrouped rows, narrow", width: 45, height: 12, rows: destinationRows()},
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

	// processRows is grouped-by-PID-shaped data (PID and Connections, no
	// local/remote address). GroupByPID now also carries REMOTE, HOSTNAME and
	// AGE, so the terminal has to be wide enough to leave PROCESS the room
	// for the full label to survive untruncated.
	m := newTestModel(processRows(), 159, 12)
	m.grouping = aggregate.GroupByPID

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

// sgrCodes returns the numeric parameters of the first SGR escape sequence in
// s, so a test can assert an attribute is present without depending on the
// order lipgloss happens to combine them in.
func sgrCodes(t *testing.T, s string) map[string]bool {
	t.Helper()

	seq := ansiPattern.FindString(s)
	if seq == "" {
		t.Fatalf("no ANSI escape sequence in %q", s)
	}

	body := strings.TrimSuffix(strings.TrimPrefix(seq, "\x1b["), "m")
	codes := make(map[string]bool)
	for _, c := range strings.Split(body, ";") {
		codes[c] = true
	}
	return codes
}

// TestDefaultStylesRenderTheirAttributes checks the styles beyond Closed and
// Selected — which the row-rendering tests already exercise — actually carry
// the attributes their doc comments claim.
func TestDefaultStylesRenderTheirAttributes(t *testing.T) {
	withANSI(t)
	s := DefaultStyles()

	tests := []struct {
		name  string
		style lipgloss.Style
		codes []string // SGR codes: 1 bold, 2 faint, 4 underline, 7 reverse
	}{
		{name: "Header is bold", style: s.Header, codes: []string{"1"}},
		{name: "Breadcrumb is faint", style: s.Breadcrumb, codes: []string{"2"}},
		{name: "Footer is faint", style: s.Footer, codes: []string{"2"}},
		{name: "ColumnHeader is bold and underlined", style: s.ColumnHeader, codes: []string{"1", "4"}},
		{name: "Paused is bold and reversed", style: s.Paused, codes: []string{"1", "7"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rendered := tc.style.Render("x")
			got := sgrCodes(t, rendered)
			for _, code := range tc.codes {
				if !got[code] {
					t.Errorf("%s: rendered %q missing SGR code %q", tc.name, rendered, code)
				}
			}
		})
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

func TestViewUngroupedShowsLocalRemoteAndState(t *testing.T) {
	// Wide enough that LOCAL and REMOTE do not have to truncate: they share
	// the flexible width with PROCESS, and a clipped address would be a test
	// about truncation rather than about the view.
	m := newTestModel(destinationRows(), 200, 12)

	got := m.View()
	for _, want := range []string{
		"LOCAL", "REMOTE", "STATE",
		"192.168.1.10:51000", "140.82.112.3:443", "ESTABLISHED",
		"2.1 MB/s", "128.0 MB",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ungrouped view missing %q:\n%s", want, got)
		}
	}
}

func TestUpdateNavigation(t *testing.T) {
	// The live model is ungrouped, so its rows are the three connections of
	// testSnapshot: indices 0, 1 and 2.
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

func TestUpdateGroupingCyclesThroughAllThreeStates(t *testing.T) {
	m := newLiveModel()
	if m.grouping != aggregate.GroupNone {
		t.Fatalf("the model should start ungrouped")
	}

	// Ungrouped: one row per connection.
	if got := rowLabels(m); len(got) != 3 {
		t.Fatalf("rows = %v, want the three connections", got)
	}

	m, _ = press(t, m, "g")
	if m.grouping != aggregate.GroupByPID {
		t.Fatalf("g did not switch to by-PID grouping")
	}
	if got := rowLabels(m); len(got) != 3 {
		t.Errorf("rows = %v, want one row per PID (three distinct processes)", got)
	}
	if !strings.Contains(m.View(), "By PID") {
		t.Errorf("header did not follow the grouping:\n%s", m.View())
	}

	m, _ = press(t, m, "g")
	if m.grouping != aggregate.GroupByProcessName {
		t.Fatalf("g did not switch to by-process-name grouping")
	}
	if !strings.Contains(m.View(), "By Process") {
		t.Errorf("header did not follow the grouping:\n%s", m.View())
	}

	// Wraps back round to ungrouped.
	m, _ = press(t, m, "g")
	if m.grouping != aggregate.GroupNone {
		t.Errorf("g did not wrap back to ungrouped")
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

func TestInitStartsTheTicker(t *testing.T) {
	m := newTestModel(processRows(), 100, 12)

	cmd := m.Init()
	if cmd == nil {
		t.Fatalf("Init returned no command, so the render loop would never start")
	}

	if _, ok := cmd().(tickMsg); !ok {
		t.Errorf("Init's command did not produce a tickMsg")
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
	for _, binding := range allBindings(t, DefaultKeyMap()) {
		for _, k := range binding.Keys() {
			t.Run(k, func(t *testing.T) {
				// A filter already in force gives `/` something to open over.
				m := newLiveModel()
				m.filter = "1"
				m.rebuild()
				m.cursor = 1

				before := modelState(m, nil)
				next, cmd := press(t, m, k)
				after := modelState(next, cmd)

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
	return fmt.Sprintf("grouping=%d sort=%s cursor=%d rows=%v paused=%t help=%t filter=%q filtering=%t quit=%t",
		m.grouping, m.sort, m.cursor,
		rowLabels(m), m.paused, m.showHelp, m.filter, m.filtering, cmd != nil)
}

// rowLabels is the labels of the rows on screen, in order.
func rowLabels(m Model) []string {
	out := make([]string, len(m.rows))
	for i, r := range m.rows {
		out[i] = r.Label
	}
	return out
}

func TestHostnameColumnShowsTheAddressUntilItResolves(t *testing.T) {
	// A model with no resolver behind it stands in for the state every
	// destination is in on the first frame: the query has not answered, and
	// the bare address is what there is to show.
	m := newTestModel(destinationRows(), 200, 12)

	got := m.View()
	if !strings.Contains(got, "HOSTNAME") {
		t.Fatalf("ungrouped view has no hostname column:\n%s", got)
	}

	// The address appears twice on the row — once as the remote, once
	// standing in for its unresolved name — which is what tells the two
	// columns apart from a single column that happens to be wide.
	line := tableLine(t, got, "140.82.112.3")
	if n := strings.Count(line, "140.82.112.3"); n != 2 {
		t.Errorf("row shows the address %d times, want 2 (remote and unresolved hostname):\n%s", n, line)
	}
}

func TestHostnameColumnShowsResolvedNames(t *testing.T) {
	m := newResolvedModel(t, map[string]string{"140.82.112.3": "lb.github.com"}, 200, 12)

	got := m.View()
	if !strings.Contains(got, "lb.github.com") {
		t.Errorf("resolved name missing from the view:\n%s", got)
	}

	// The address it annotates stays on screen: the hostname is an extra
	// column, not a substitution, so a row can still be read as the
	// destination it is.
	if !strings.Contains(got, "140.82.112.3:443") {
		t.Errorf("the address was replaced rather than annotated:\n%s", got)
	}

	// The one that does not resolve is unaffected and still shows its address.
	line := tableLine(t, got, "2606:4700:4700::1111")
	if strings.Contains(line, "lb.github.com") {
		t.Errorf("an unresolved row borrowed another row's name:\n%s", line)
	}
}

func TestHostnamePrefersRowSNIOverDNS(t *testing.T) {
	m := newResolvedModel(t, map[string]string{"140.82.112.3": "lb.github.com"}, 200, 12)

	row := aggregate.Row{RemoteAddr: "140.82.112.3", Hostname: "own.example.com"}
	if got := m.resolveHostname(row); got != "own.example.com" {
		t.Errorf("hostname() = %q, want the row's own SNI %q, not the resolved DNS name", got, "own.example.com")
	}
}

func TestHostnameFallsBackToPerIPCacheWhenRowHasNoSNI(t *testing.T) {
	m := newTestModel(nil, 200, 12)
	m.hostnameCache = dpi.NewHostnameCache(dpi.DefaultHostnameCacheCapacity, dpi.DefaultHostnameCacheTTL)
	m.hostnameCache.Put("140.82.112.3", "seeded-by-another-connection.example.com", m.now)

	withSNI := aggregate.Row{RemoteAddr: "140.82.112.3", Hostname: "own.example.com"}
	withoutSNI := aggregate.Row{RemoteAddr: "140.82.112.3"}

	// The same IP genuinely serving two different hostnames: the connection
	// with its own SNI must keep showing it, unaffected by the cache: only
	// the connection with none of its own borrows the fallback.
	if got := m.resolveHostname(withSNI); got != "own.example.com" {
		t.Errorf("hostname() = %q, want the row's own SNI %q unaffected by the cache", got, "own.example.com")
	}
	if got := m.resolveHostname(withoutSNI); got != "seeded-by-another-connection.example.com" {
		t.Errorf("hostname() = %q, want the per-IP cache fallback %q", got, "seeded-by-another-connection.example.com")
	}
}

func TestHostnameFallsBackToDNSWhenNoSNIOrCacheEntry(t *testing.T) {
	m := newResolvedModel(t, map[string]string{"140.82.112.3": "lb.github.com"}, 200, 12)
	m.hostnameCache = dpi.NewHostnameCache(dpi.DefaultHostnameCacheCapacity, dpi.DefaultHostnameCacheTTL)

	row := aggregate.Row{RemoteAddr: "140.82.112.3"}
	if got := m.resolveHostname(row); got != "lb.github.com" {
		t.Errorf("hostname() = %q, want the resolved DNS name %q", got, "lb.github.com")
	}
}

func TestHostnameFallsBackToBareAddressWhenNothingResolves(t *testing.T) {
	m := newTestModel(nil, 200, 12)

	row := aggregate.Row{RemoteAddr: "9.9.9.9"}
	if got := m.resolveHostname(row); got != "9.9.9.9" {
		t.Errorf("hostname() = %q, want the bare address %q", got, "9.9.9.9")
	}
}

func TestStateColumnHiddenWhenGrouped(t *testing.T) {
	// GroupByPID and GroupByProcessName both roll up per remote endpoint, so
	// REMOTE and HOSTNAME still mean something and must appear; STATE does
	// not, since a grouped row can roll up more than one connection's state.
	m := newTestModel(processRows(), 120, 12)
	m.grouping = aggregate.GroupByPID

	got := m.View()
	if strings.Contains(got, "STATE") {
		t.Errorf("grouped view has a STATE column:\n%s", got)
	}
	for _, wanted := range []string{"HOSTNAME", "REMOTE"} {
		if !strings.Contains(got, wanted) {
			t.Errorf("grouped view is missing its %s column:\n%s", wanted, got)
		}
	}
}

func TestFilterMatchesResolvedHostnames(t *testing.T) {
	m := newResolvedModel(t, map[string]string{"140.82.112.3": "lb.github.com"}, 200, 12)
	m.snap = testSnapshot()
	m.rebuild()

	m = pressAll(t, m, "/", "g", "i", "t", "h", "u", "b", "enter")

	// Both connections to that host match, on either port, and the one to a
	// different host does not: the filter is reading a name that is nowhere
	// in the row's label.
	got := rowLabels(m)
	if len(got) != 2 {
		t.Fatalf("rows = %v, want both connections to the github destination", got)
	}
	for _, label := range got {
		if label != "com.apple.WebKit.Networking" && label != "Google Chrome Helper" {
			t.Errorf("rows = %v, want only the processes talking to the github destination", got)
		}
	}
}

// tableLine returns the single rendered row containing want, so a test can
// assert on one row rather than on the whole frame.
func tableLine(t *testing.T, view, want string) string {
	t.Helper()

	var found []string
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, want) && !strings.Contains(line, "HOSTNAME") {
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d rows contain %q, want exactly 1:\n%s", len(found), want, view)
	}
	return found[0]
}

func TestFilterInputCapturesKeystrokes(t *testing.T) {
	m := newLiveModel()

	m, cmd := press(t, m, "/")
	if !m.filtering {
		t.Fatalf("/ did not open the filter input")
	}
	if cmd != nil {
		t.Errorf("opening the filter input returned a command, want none")
	}

	// Every navigation binding is a bare letter, so the characters most likely
	// to be typed into a filter are the ones that would otherwise quit the
	// program or freeze the capture mid-word.
	for _, k := range []string{"q", "p", "g", "s", "r", "j", "k", "G", "?"} {
		var cmd tea.Cmd
		m, cmd = press(t, m, k)

		if cmd != nil {
			t.Errorf("typing %q into the filter returned a command, want none", k)
		}
	}

	if m.paused {
		t.Errorf("typing \"p\" into the filter paused the capture")
	}
	if m.showHelp {
		t.Errorf("typing \"?\" into the filter opened the help overlay")
	}
	if m.sort != SortRate {
		t.Errorf("typing into the filter changed the sort to %s", m.sort)
	}
	if m.grouping != aggregate.GroupNone {
		t.Errorf("typing into the filter changed the grouping")
	}
	if got, want := m.filter, "qpgsrjkG?"; got != want {
		t.Errorf("filter = %q, want every keystroke as text %q", got, want)
	}
}

func TestFilterInputCtrlCStillQuits(t *testing.T) {
	// The one key a text field must not swallow: it is the terminal's own
	// interrupt rather than a letter anyone types, and a filter that ate it
	// would leave no way out of the program at all.
	m := pressAll(t, newLiveModel(), "/", "s")

	_, cmd := press(t, m, "ctrl+c")
	if cmd == nil {
		t.Errorf("ctrl+c while filtering did not quit")
	}
}

func TestHelpOverlayClosesWithQuestionMarkOrEsc(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "same key toggles it off", key: "?"},
		{name: "esc also dismisses it", key: "esc"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := press(t, newLiveModel(), "?")
			if !m.showHelp {
				t.Fatalf("? did not open the help overlay")
			}

			m, _ = press(t, m, tc.key)
			if m.showHelp {
				t.Errorf("%q did not close the help overlay", tc.key)
			}
		})
	}
}

// TestHelpOverlayIgnoresEverythingElse checks that the keys which normally
// change the model are no-ops while help is showing: everything underneath
// the overlay is out of sight, so acting on it would change a view the user
// cannot see.
func TestHelpOverlayIgnoresEverythingElse(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "cursor movement", key: "j"},
		{name: "pause", key: "p"},
		{name: "grouping", key: "g"},
		{name: "filter", key: "/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := press(t, newLiveModel(), "?")
			if !m.showHelp {
				t.Fatalf("? did not open the help overlay")
			}
			before := modelState(m, nil)

			m, cmd := press(t, m, tc.key)

			if !m.showHelp {
				t.Errorf("%q closed the help overlay, want it to stay open", tc.key)
			}
			if got := modelState(m, cmd); got != before {
				t.Errorf("%q changed the model while help was open:\n%s\nwant:\n%s", tc.key, got, before)
			}
		})
	}
}

func TestFilterNarrowsTheTableAsItIsTyped(t *testing.T) {
	m := newLiveModel()
	if len(m.rows) != 3 {
		t.Fatalf("setup has %d rows, want 3", len(m.rows))
	}

	m = pressAll(t, m, "/", "s", "s", "h")
	if got := rowLabels(m); len(got) != 1 || got[0] != "sshd" {
		t.Errorf("rows = %v, want just sshd while typing", got)
	}
}

func TestFilterEnterCommits(t *testing.T) {
	m := pressAll(t, newLiveModel(), "/", "s", "s", "h", "enter")

	if m.filtering {
		t.Errorf("enter did not close the filter input")
	}
	if m.filter != "ssh" {
		t.Errorf("filter = %q, want %q", m.filter, "ssh")
	}
	if got := rowLabels(m); len(got) != 1 || got[0] != "sshd" {
		t.Errorf("rows = %v, want just sshd", got)
	}
}

func TestFilterEscCancelsAndRestores(t *testing.T) {
	m := pressAll(t, newLiveModel(), "/", "s", "s", "h", "enter")

	m = pressAll(t, m, "/", "c", "h", "r", "o")
	if got := rowLabels(m); len(got) != 1 || got[0] != "Google Chrome Helper" {
		t.Errorf("rows = %v, want the new filter previewed", got)
	}

	m = pressAll(t, m, "esc")
	if m.filtering {
		t.Errorf("esc did not close the filter input")
	}
	if m.filter != "ssh" {
		t.Errorf("filter = %q, want the previous filter %q back", m.filter, "ssh")
	}
	if got := rowLabels(m); len(got) != 1 || got[0] != "sshd" {
		t.Errorf("rows = %v, want the previous filter's rows back", got)
	}
}

func TestFilterIsClearedByCommittingNothing(t *testing.T) {
	m := pressAll(t, newLiveModel(), "/", "s", "s", "h", "enter")
	if len(m.rows) != 1 {
		t.Fatalf("setup has %d rows, want 1", len(m.rows))
	}

	// The input opens empty, so this is the whole gesture for taking a filter
	// off again — and the footer says so while it is open.
	m = pressAll(t, m, "/", "enter")

	if m.filter != "" {
		t.Errorf("filter = %q, want it cleared", m.filter)
	}
	if len(m.rows) != 3 {
		t.Errorf("rows = %v, want the whole table back", rowLabels(m))
	}
}

func TestFilterIsVisibleWhileItIsInForce(t *testing.T) {
	m := pressAll(t, newLiveModel(), "/", "s", "s", "h")

	// While typing, the footer is the input: the key hints it displaces are
	// the ones that do nothing until the edit is over.
	open := m.View()
	if !strings.Contains(open, filterPrompt+"ssh") {
		t.Errorf("the filter input is not on screen:\n%s", open)
	}
	if !strings.Contains(open, filterHint) {
		t.Errorf("the filter input does not say how to close it:\n%s", open)
	}
	if strings.Contains(open, "cycle sort") {
		t.Errorf("the key hints are still shown behind the filter input:\n%s", open)
	}

	// Once committed the input goes away, and the header carries the filter
	// instead: rows silently missing from a table look exactly like traffic
	// that stopped.
	m = pressAll(t, m, "enter")
	committed := m.View()
	if !strings.Contains(committed, "filter: ssh") {
		t.Errorf("the header does not name the filter in force:\n%s", committed)
	}
	if strings.Contains(committed, filterHint) {
		t.Errorf("the filter input is still on screen after enter:\n%s", committed)
	}

	// And the footer offers the key that gets it back off again, which it does
	// not do the rest of the time.
	if !strings.Contains(committed, "/ filter") {
		t.Errorf("the footer does not say how to change the filter:\n%s", committed)
	}
	if strings.Contains(newLiveModel().View(), "/ filter") {
		t.Errorf("the footer offers the filter hint with no filter in force")
	}
}

func TestFilterHeaderTruncatesALongFilter(t *testing.T) {
	// The filter is the one part of the status bar the user types, so it is
	// the one part that could otherwise shove everything else off the line.
	m := newLiveModel()
	m.filter = strings.Repeat("x", 200)

	got := m.viewHeader()
	if w := lipgloss.Width(got); w != 100 {
		t.Errorf("header width = %d, want 100", w)
	}
	if !strings.Contains(got, "…") {
		t.Errorf("a 200-character filter was not truncated:\n%s", got)
	}
}

func TestEmptyTableSaysWhyItIsEmpty(t *testing.T) {
	tests := []struct {
		name  string
		model func() Model
		want  string
	}{
		{
			name:  "nothing captured yet",
			model: func() Model { return newLiveModel() },
			want:  emptyMessage,
		},
		{
			// The filter wins over the idle-capture message: it is the thing
			// the user typed a moment ago, and the header is already naming
			// it a line above.
			name:  "a filter that matches nothing",
			model: func() Model { return pressAll(t, newLiveModel(), "/", "z", "z", "z", "enter") },
			want:  emptyFilterMessage,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.model()
			if tc.want == emptyMessage {
				m.snap = aggregate.Snapshot{At: testNow}
				m.rebuild()
			}

			if len(m.rows) != 0 {
				t.Fatalf("setup has %d rows, want none", len(m.rows))
			}
			if got := m.View(); !strings.Contains(got, tc.want) {
				t.Errorf("empty table does not say %q:\n%s", tc.want, got)
			}
		})
	}
}
