package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/boyvinall/mac-nethogs/aggregate"
)

// columnTitles is the shorthand the layout tests assert against.
func columnTitles(cols []column) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = c.title
	}
	return out
}

func TestRenderRowsAlign(t *testing.T) {
	cols := fitColumns(tableColumns(ModeProcess, aggregate.GroupByIP), 100)
	want := tableWidth(cols)

	if got := lipgloss.Width(tableHeader(cols)); got != want {
		t.Errorf("header width = %d, want %d", got, want)
	}

	// Every data line must be exactly as wide as the header, or the columns
	// stop lining up the moment a value's length changes.
	for i, line := range renderRows(processRows(), cols) {
		if got := lipgloss.Width(line); got != want {
			t.Errorf("row %d width = %d, want %d: %q", i, got, want, line)
		}
	}
}

func TestRenderRowsColumnOffsetsAreStable(t *testing.T) {
	cols := fitColumns(tableColumns(ModeProcess, aggregate.GroupByIP), 100)
	lines := renderRows(processRows(), cols)

	// The right-hand edge of each column is a fixed offset. Checking that the
	// cell boundaries hold across rows with wildly different value lengths is
	// what proves the numeric columns are right-aligned rather than merely
	// padded.
	offset := 0
	for _, c := range cols {
		end := offset + c.width
		for i, line := range lines {
			cell := []rune(line)[offset:end]
			if len(cell) != c.width {
				t.Fatalf("row %d column %q: cell width %d, want %d", i, c.title, len(cell), c.width)
			}
			if c.align == alignRight && strings.HasSuffix(string(cell), " ") {
				t.Errorf("row %d column %q = %q, right-aligned cell must not end in padding", i, c.title, string(cell))
			}
		}
		offset = end + colGap
	}
}

func TestRenderRowShowsRateAndTotalTogether(t *testing.T) {
	cols := fitColumns(tableColumns(ModeProcess, aggregate.GroupByIP), 100)
	line := renderRow(processRows()[0], cols)

	// The plan is explicit that rate and cumulative total are not a toggle, so
	// both must be on the same line at every width the table renders at.
	for _, want := range []string{"2.1 MB/s", "180.0 KB/s", "128.0 MB", "12.0 MB", "412", "14"} {
		if !strings.Contains(line, want) {
			t.Errorf("row %q missing %q", line, want)
		}
	}
}

func TestTableColumnsByMode(t *testing.T) {
	tests := []struct {
		name     string
		mode     Mode
		grouping aggregate.Grouping
		want     []string
	}{
		{
			name: "process", mode: ModeProcess, grouping: aggregate.GroupByIP,
			want: []string{"PROCESS", "PID", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL", "CONN"},
		},
		{
			name: "destination by ip", mode: ModeDestination, grouping: aggregate.GroupByIP,
			want: []string{"HOST", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL", "CONN"},
		},
		{
			name: "destination by ip:port", mode: ModeDestination, grouping: aggregate.GroupByIPPort,
			want: []string{"HOST:PORT", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL", "CONN"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := columnTitles(tableColumns(tc.mode, tc.grouping))
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("columns = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFitColumnsNarrowPolicy(t *testing.T) {
	tests := []struct {
		name       string
		width      int
		want       []string
		labelWidth int
	}{
		{
			name: "roomy", width: 120,
			want:       []string{"PROCESS", "PID", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL", "CONN"},
			labelWidth: 57,
		},
		{
			name: "typical", width: 100,
			want:       []string{"PROCESS", "PID", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL", "CONN"},
			labelWidth: 37,
		},
		{
			name: "connections dropped first", width: 70,
			want:       []string{"PROCESS", "PID", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: 14,
		},
		{
			name: "pid dropped second", width: 60,
			want:       []string{"PROCESS", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: 12,
		},
		{
			// Rate and total are never traded away, so below the essential
			// set the table stops shrinking and the caller clips it.
			name: "essential floor", width: 30,
			want:       []string{"PROCESS", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: minLabelWidth,
		},
		{
			// An unset width means no tea.WindowSizeMsg has arrived yet.
			name: "unknown width", width: 0,
			want:       []string{"PROCESS", "PID", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL", "CONN"},
			labelWidth: 37,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cols := fitColumns(tableColumns(ModeProcess, aggregate.GroupByIP), tc.width)

			if got := columnTitles(cols); strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("columns = %v, want %v", got, tc.want)
			}
			if got := cols[labelColumn].width; got != tc.labelWidth {
				t.Errorf("label width = %d, want %d", got, tc.labelWidth)
			}

			// Whatever survives must still fill the terminal exactly, except
			// at the floor where the minimum is wider than the terminal.
			if w := tableWidth(cols); tc.width >= 60 && w != tc.width {
				t.Errorf("table width = %d, want %d", w, tc.width)
			}
		})
	}
}

func TestFitColumnsDoesNotMutateInput(t *testing.T) {
	cols := tableColumns(ModeProcess, aggregate.GroupByIP)
	before := len(cols)

	fitColumns(cols, 40)

	if len(cols) != before || cols[labelColumn].width != 0 {
		t.Errorf("fitColumns mutated its input: len=%d label width=%d", len(cols), cols[labelColumn].width)
	}
}

func TestLabelTruncatesAtNarrowWidth(t *testing.T) {
	cols := fitColumns(tableColumns(ModeProcess, aggregate.GroupByIP), 60)
	line := renderRow(processRows()[0], cols)

	label := string([]rune(line)[:cols[labelColumn].width])
	if label != "com.apple.W…" {
		t.Errorf("label = %q, want %q", label, "com.apple.W…")
	}

	// Truncation, not wrapping: one row is always one line.
	if strings.Contains(line, "\n") {
		t.Errorf("row wrapped onto a second line: %q", line)
	}
	if got := lipgloss.Width(line); got != 60 {
		t.Errorf("row width = %d, want 60", got)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name string
		s    string
		w    int
		want string
	}{
		{name: "fits exactly", s: "sshd", w: 4, want: "sshd"},
		{name: "shorter than cell", s: "sshd", w: 8, want: "sshd"},
		{name: "one over", s: "sshd", w: 3, want: "ss…"},
		{name: "single cell", s: "sshd", w: 1, want: "…"},
		{name: "no room", s: "sshd", w: 0, want: ""},
		{name: "negative", s: "sshd", w: -3, want: ""},
		{name: "empty", s: "", w: 5, want: ""},
		{name: "wide runes", s: "日本語です", w: 5, want: "日本…"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := truncate(tc.s, tc.w)
			if got != tc.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tc.s, tc.w, got, tc.want)
			}
			if tc.w > 0 && lipgloss.Width(got) > tc.w {
				t.Errorf("truncate(%q, %d) = %q, %d cells wide", tc.s, tc.w, got, lipgloss.Width(got))
			}
		})
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		name  string
		s     string
		w     int
		align alignment
		want  string
	}{
		{name: "left", s: "sshd", w: 8, align: alignLeft, want: "sshd    "},
		{name: "right", s: "sshd", w: 8, align: alignRight, want: "    sshd"},
		{name: "exact", s: "sshd", w: 4, align: alignRight, want: "sshd"},
		{name: "truncated", s: "sshd", w: 3, align: alignRight, want: "ss…"},
		{name: "empty right", s: "", w: 3, align: alignRight, want: "   "},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pad(tc.s, tc.w, tc.align); got != tc.want {
				t.Errorf("pad(%q, %d) = %q, want %q", tc.s, tc.w, got, tc.want)
			}
		})
	}
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		name string
		n    uint64
		want string
	}{
		{name: "zero", n: 0, want: "0 B"},
		{name: "one", n: 1, want: "1 B"},
		{name: "just under a kilobyte", n: 1023, want: "1023 B"},
		{name: "exactly a kilobyte", n: 1024, want: "1.0 KB"},
		{name: "just over a kilobyte", n: 1025, want: "1.0 KB"},
		{name: "one and a half", n: 1536, want: "1.5 KB"},
		{name: "widest kilobyte form", n: 1048575, want: "1024.0 KB"},
		{name: "exactly a megabyte", n: 1048576, want: "1.0 MB"},
		{name: "gigabyte", n: 1 << 30, want: "1.0 GB"},
		{name: "terabyte", n: 1 << 40, want: "1.0 TB"},
		{name: "petabyte", n: 1 << 50, want: "1.0 PB"},
		{name: "exabyte", n: 1 << 60, want: "1.0 EB"},
		{name: "max uint64 stays in range", n: ^uint64(0), want: "16.0 EB"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := humanBytes(tc.n)
			if got != tc.want {
				t.Errorf("humanBytes(%d) = %q, want %q", tc.n, got, tc.want)
			}

			// The total column is sized from the widest form this can return;
			// if that ever grows, the column has to grow with it.
			if lipgloss.Width(got) > totalWidth {
				t.Errorf("humanBytes(%d) = %q, wider than the %d-cell total column", tc.n, got, totalWidth)
			}
		})
	}
}

func TestHumanRate(t *testing.T) {
	tests := []struct {
		name string
		bps  float64
		want string
	}{
		{name: "idle", bps: 0, want: "0 B/s"},
		{name: "sub-byte truncates down", bps: 0.9, want: "0 B/s"},
		{name: "sub-kilobyte", bps: 512, want: "512 B/s"},
		{name: "exactly a kilobyte", bps: 1024, want: "1.0 KB/s"},
		{name: "fractional bytes are dropped", bps: 1536.75, want: "1.5 KB/s"},
		{name: "widest kilobyte form", bps: 1048575, want: "1024.0 KB/s"},
		{name: "megabyte", bps: 2202009, want: "2.1 MB/s"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := humanRate(tc.bps)
			if got != tc.want {
				t.Errorf("humanRate(%v) = %q, want %q", tc.bps, got, tc.want)
			}
			if lipgloss.Width(got) > rateWidth {
				t.Errorf("humanRate(%v) = %q, wider than the %d-cell rate column", tc.bps, got, rateWidth)
			}
		})
	}
}
