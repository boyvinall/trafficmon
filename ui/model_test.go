package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/boyvinall/mac-nethogs/aggregate"
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

	m.stack.Push(Frame{Mode: ModeDestination, Label: "Process: Chrome (pid 4821)"})
	drilled := m.viewFooter()
	if !strings.Contains(drilled, "back") {
		t.Errorf("drilled-in footer %q should offer esc", drilled)
	}
	if len(m.footerKeys()) != len(m.keys.ShortHelp())+1 {
		t.Errorf("drilled-in footer should add exactly one hint")
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
		{name: "empty", width: 100, height: 12, rows: nil},
		{name: "help overlay", width: 100, height: 12, rows: processRows(), showHelp: true},
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
