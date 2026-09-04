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
	cols := fitColumns(tableColumns(aggregate.GroupByPID, nil), 100)
	want := tableWidth(cols)

	// The header is checked under every sort key, because the marker the
	// active one adds to a title has to fit inside the column it marks.
	for k := SortKey(0); k < numSortKeys; k++ {
		if got := lipgloss.Width(tableHeader(cols, k)); got != want {
			t.Errorf("header width sorted by %s = %d, want %d", k, got, want)
		}
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
	cols := fitColumns(tableColumns(aggregate.GroupByPID, nil), 100)
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
	cols := fitColumns(tableColumns(aggregate.GroupByPID, nil), 100)
	line := renderRow(processRows()[0], cols)

	// The plan is explicit that rate and cumulative total are not a toggle, so
	// both must be on the same line at every width the table renders at.
	for _, want := range []string{"2.1 MB/s", "180.0 KB/s", "128.0 MB", "12.0 MB", "412", "14"} {
		if !strings.Contains(line, want) {
			t.Errorf("row %q missing %q", line, want)
		}
	}
}

func TestTableColumnsByGrouping(t *testing.T) {
	tests := []struct {
		name     string
		grouping aggregate.Grouping
		hostname func(aggregate.Row) string
		want     []string
	}{
		{
			name: "ungrouped, no hostname", grouping: aggregate.GroupNone,
			want: []string{"PROCESS", "LOCAL", "REMOTE", "PROTO", "PID", "STATE", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
		},
		{
			name: "ungrouped, with hostname", grouping: aggregate.GroupNone, hostname: stubHostname,
			want: []string{"PROCESS", "LOCAL", "REMOTE", "HOSTNAME", "PROTO", "PID", "STATE", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
		},
		{
			name: "by PID", grouping: aggregate.GroupByPID,
			want: []string{"PROCESS", "LOCAL", "REMOTE", "PID", "CONN", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
		},
		{
			name: "by PID, with hostname", grouping: aggregate.GroupByPID, hostname: stubHostname,
			want: []string{"PROCESS", "LOCAL", "REMOTE", "HOSTNAME", "PID", "CONN", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
		},
		{
			name: "by process name", grouping: aggregate.GroupByProcessName,
			want: []string{"PROCESS", "REMOTE", "CONN", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
		},
		{
			name: "by process name, with hostname", grouping: aggregate.GroupByProcessName, hostname: stubHostname,
			want: []string{"PROCESS", "REMOTE", "HOSTNAME", "CONN", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := columnTitles(tableColumns(tc.grouping, tc.hostname))
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("columns = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProtoLabel(t *testing.T) {
	tests := []struct {
		name string
		row  aggregate.Row
		want string
	}{
		{name: "tcp", row: aggregate.Row{Proto: "tcp"}, want: "TCP"},
		{name: "udp", row: aggregate.Row{Proto: "udp"}, want: "UDP"},
		{name: "icmp", row: aggregate.Row{Proto: "icmp"}, want: "ICMP"},
		{name: "arp", row: aggregate.Row{Proto: "arp"}, want: "ARP"},
		{
			name: "udp on the dns port shows dns, not udp",
			row:  aggregate.Row{Proto: "udp", RemotePort: 53},
			want: "DNS",
		},
		{
			name: "tcp on the local dns port shows dns too",
			row:  aggregate.Row{Proto: "tcp", LocalPort: 53},
			want: "DNS",
		},
		{
			name: "icmp on port 53 is not dns -- icmp has no ports",
			row:  aggregate.Row{Proto: "icmp", LocalPort: 53},
			want: "ICMP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := protoLabel(tt.row); got != tt.want {
				t.Errorf("protoLabel(%+v) = %q, want %q", tt.row, got, tt.want)
			}
		})
	}
}

func TestPIDColumnShowsDashForUnattributedRows(t *testing.T) {
	col := pidColumn()

	if got := col.cell(aggregate.Row{PID: 0}); got != "-" {
		t.Errorf("pidColumn cell for PID 0 = %q, want %q", got, "-")
	}
	if got := col.cell(aggregate.Row{PID: 1234}); got != "1234" {
		t.Errorf("pidColumn cell for PID 1234 = %q, want %q", got, "1234")
	}
}

func TestPIDAndConnColumnsTruncateFromTheLeft(t *testing.T) {
	// PID and CONN have no formatter-enforced width bound the way rate/total
	// do (humanRate/humanBytes are provably within their column). This proves
	// that if either value ever overflows its column anyway, the low-order
	// digits — the ones that actually distinguish it from a neighbouring
	// value — are what survive, rather than being the ones dropped. GroupByPID
	// is the one grouping where both columns are on screen together.
	row := aggregate.Row{PID: 2147483647, Connections: 123456}
	cols := tableColumns(aggregate.GroupByPID, nil)

	tests := []struct {
		title string
		want  string
	}{
		{title: "PID", want: "…83647"},
		{title: "CONN", want: "…3456"},
	}

	for _, tc := range tests {
		t.Run(tc.title, func(t *testing.T) {
			for _, c := range cols {
				if c.title != tc.title {
					continue
				}
				if !c.truncLeft {
					t.Fatalf("column %q does not set truncLeft; an overflow would drop its low-order digits", tc.title)
				}
				if got := pad(c.cell(row), c.width, c.align, c.truncLeft); got != tc.want {
					t.Errorf("%s column = %q, want %q", tc.title, got, tc.want)
				}
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
			want:       []string{"PROCESS", "LOCAL", "REMOTE", "PID", "CONN", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: 19,
		},
		{
			name: "typical", width: 97,
			want:       []string{"PROCESS", "LOCAL", "REMOTE", "PID", "CONN", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: 10,
		},
		{
			name: "connections dropped first", width: 90,
			want:       []string{"PROCESS", "LOCAL", "REMOTE", "PID", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: 10,
		},
		{
			// Rate and total are never traded away, so below the essential
			// set the table stops shrinking and the caller clips it. REMOTE
			// is essential in every grouping now, so PID drops straight to
			// that floor rather than there being a width where it alone is
			// gone but the row still fits its own width.
			name: "pid dropped, at the essential floor", width: 82,
			want:       []string{"PROCESS", "LOCAL", "REMOTE", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: minLabelWidth,
		},
		{
			name: "essential floor", width: 30,
			want:       []string{"PROCESS", "LOCAL", "REMOTE", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: minLabelWidth,
		},
		{
			// An unset width means no tea.WindowSizeMsg has arrived yet.
			name: "unknown width", width: 0,
			want:       []string{"PROCESS", "LOCAL", "REMOTE", "PID", "CONN", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: 11,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cols := fitColumns(tableColumns(aggregate.GroupByPID, nil), tc.width)

			if got := columnTitles(cols); strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("columns = %v, want %v", got, tc.want)
			}
			if got := cols[labelColumn].width; got != tc.labelWidth {
				t.Errorf("label width = %d, want %d", got, tc.labelWidth)
			}

			// Whatever survives must still fill the terminal exactly, except
			// at the floor where the minimum is wider than the terminal.
			if w := tableWidth(cols); tc.width >= 82 && w != tc.width {
				t.Errorf("table width = %d, want %d", w, tc.width)
			}
		})
	}
}

func TestFitColumnsDoesNotMutateInput(t *testing.T) {
	cols := tableColumns(aggregate.GroupByPID, nil)
	before := len(cols)

	fitColumns(cols, 40)

	if len(cols) != before || cols[labelColumn].width != 0 {
		t.Errorf("fitColumns mutated its input: len=%d label width=%d", len(cols), cols[labelColumn].width)
	}
}

func TestLabelTruncatesAtNarrowWidth(t *testing.T) {
	cols := fitColumns(tableColumns(aggregate.GroupByPID, nil), 82)
	line := renderRow(processRows()[0], cols)

	label := string([]rune(line)[:cols[labelColumn].width])
	if label != "com.apple…" {
		t.Errorf("label = %q, want %q", label, "com.apple…")
	}

	// Truncation, not wrapping: one row is always one line.
	if strings.Contains(line, "\n") {
		t.Errorf("row wrapped onto a second line: %q", line)
	}
	if got := lipgloss.Width(line); got != 82 {
		t.Errorf("row width = %d, want 82", got)
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

func TestTruncateLeft(t *testing.T) {
	tests := []struct {
		name string
		s    string
		w    int
		want string
	}{
		{name: "fits exactly", s: "sshd", w: 4, want: "sshd"},
		{name: "shorter than cell", s: "sshd", w: 8, want: "sshd"},
		// The end of the string is the part worth keeping: it is a value's
		// low-order digits, and the digits that distinguish it from a
		// neighbour are the ones on the right.
		{name: "one over", s: "sshd", w: 3, want: "…hd"},
		{name: "single cell", s: "sshd", w: 1, want: "…"},
		{name: "no room", s: "sshd", w: 0, want: ""},
		{name: "negative", s: "sshd", w: -3, want: ""},
		{name: "empty", s: "", w: 5, want: ""},
		{name: "wide runes", s: "日本語です", w: 5, want: "…です"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateLeft(tc.s, tc.w)
			if got != tc.want {
				t.Errorf("truncateLeft(%q, %d) = %q, want %q", tc.s, tc.w, got, tc.want)
			}
			if tc.w > 0 && lipgloss.Width(got) > tc.w {
				t.Errorf("truncateLeft(%q, %d) = %q, %d cells wide", tc.s, tc.w, got, lipgloss.Width(got))
			}
		})
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		name      string
		s         string
		w         int
		align     alignment
		truncLeft bool
		want      string
	}{
		{name: "left", s: "sshd", w: 8, align: alignLeft, want: "sshd    "},
		{name: "right", s: "sshd", w: 8, align: alignRight, want: "    sshd"},
		{name: "exact", s: "sshd", w: 4, align: alignRight, want: "sshd"},
		{name: "truncated", s: "sshd", w: 3, align: alignRight, want: "ss…"},
		{name: "empty right", s: "", w: 3, align: alignRight, want: "   "},
		{
			// PID and CONN pass truncLeft so the low-order digits survive an
			// overflow instead of the high-order ones.
			name: "truncated from the left", s: "123456", w: 4, align: alignRight, truncLeft: true, want: "…456",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pad(tc.s, tc.w, tc.align, tc.truncLeft); got != tc.want {
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

func TestTableHeaderMarksTheSortedColumns(t *testing.T) {
	tests := []struct {
		name   string
		k      SortKey
		marked []string
	}{
		// The rate and total sorts add both directions together, so both of
		// the columns they read are marked.
		{name: "rate", k: SortRate, marked: []string{"↓ RATE", "↑ RATE"}},
		{name: "total", k: SortTotal, marked: []string{"↓ TOTAL", "↑ TOTAL"}},
		{name: "connections", k: SortConnections, marked: []string{"CONN"}},
	}

	cols := fitColumns(tableColumns(aggregate.GroupByPID, nil), 100)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			header := tableHeader(cols, tc.k)

			// A marker that does not fit is worse than none at all: pad would
			// truncate the title it was added to, so the column would lose its
			// name to gain a mark.
			if strings.Contains(header, "…") {
				t.Errorf("the %s marker pushed a title out of its column: %q", tc.k, header)
			}

			want := make(map[string]bool, len(tc.marked))
			for _, title := range tc.marked {
				want[title] = true
			}
			for _, c := range cols {
				got := strings.Contains(header, sortMarker+c.title)
				if got != want[c.title] {
					t.Errorf("column %q marked = %v, want %v, in %q", c.title, got, want[c.title], header)
				}
			}
		})
	}
}

func TestSortKeyCycle(t *testing.T) {
	// `s` visits every key and comes back to where it started, so the user can
	// always get back to a sort by pressing it again rather than having to
	// remember which other key undoes it.
	seen := map[SortKey]bool{}
	k := SortRate
	for range numSortKeys {
		if seen[k] {
			t.Fatalf("the cycle repeats %s before visiting every key", k)
		}
		seen[k] = true
		k = k.next()
	}
	if k != SortRate {
		t.Errorf("the cycle ended on %s, want it wrapped back to %s", k, SortRate)
	}
	if len(seen) != int(numSortKeys) {
		t.Errorf("the cycle visited %d keys, want %d", len(seen), numSortKeys)
	}
}

func TestSortKeyToggleRate(t *testing.T) {
	tests := []struct {
		name string
		from SortKey
		want SortKey
	}{
		{name: "rate to total", from: SortRate, want: SortTotal},
		{name: "total back to rate", from: SortTotal, want: SortRate},
		// `r` chooses between the two bandwidth numbers, and the connection
		// count is neither, so it lands on rate rather than doing nothing.
		{name: "connections lands on rate", from: SortConnections, want: SortRate},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.from.toggleRate(); got != tc.want {
				t.Errorf("%s.toggleRate() = %s, want %s", tc.from, got, tc.want)
			}
		})
	}
}

func TestSortRowsByKey(t *testing.T) {
	tests := []struct {
		name string
		k    SortKey
		want []string
	}{
		{name: "rate", k: SortRate, want: []string{"412", "980", "22", "-1", "1"}},
		{name: "total", k: SortTotal, want: []string{"412", "980", "22", "-1", "1"}},
		{name: "connections", k: SortConnections, want: []string{"412", "980", "-1", "22", "1"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows := processRows()
			sortRows(rows, tc.k)

			got := make([]string, len(rows))
			for i, r := range rows {
				got[i] = r.Key
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("sorted by %s = %v, want %v", tc.k, got, tc.want)
			}
		})
	}
}

func TestSortRowsByKeyIsStableOnTies(t *testing.T) {
	// sort.SliceStable is used deliberately so that rows tied on the active
	// key keep the order they arrived in; processRows never ties on any key,
	// so TestSortRowsByKey alone never exercises that. This does.
	rows := []aggregate.Row{
		{Key: "a", RateInBps: 100, Connections: 5},
		{Key: "b", RateInBps: 100, Connections: 5},
		{Key: "c", RateInBps: 200, Connections: 5},
	}

	sortRows(rows, SortRate)

	got := make([]string, len(rows))
	for i, r := range rows {
		got[i] = r.Key
	}
	// c sorts first on its higher rate; a and b tie and must come out in the
	// order they went in rather than swapping.
	if want := []string{"c", "a", "b"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("sorted by rate = %v, want %v", got, want)
	}
}

func TestFitColumnsDropsHostnameThenStateThenPID(t *testing.T) {
	tests := []struct {
		name       string
		width      int
		want       []string
		labelWidth int
	}{
		{
			// The four flexible columns split what the fixed ones leave, so
			// a wide terminal spends its extra cells on all of them.
			name: "roomy", width: 200,
			want:       []string{"PROCESS", "LOCAL", "REMOTE", "HOSTNAME", "PROTO", "PID", "STATE", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: 32,
		},
		{
			name: "typical", width: 140,
			want:       []string{"PROCESS", "LOCAL", "REMOTE", "HOSTNAME", "PROTO", "PID", "STATE", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: 17,
		},
		{
			// The hostname goes before everything else, because it is the
			// only column that annotates another one rather than carrying
			// anything of its own: the address it names is still on screen
			// without it.
			name: "hostname dropped first", width: 110,
			want:       []string{"PROCESS", "LOCAL", "REMOTE", "PROTO", "PID", "STATE", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: 11,
		},
		{
			name: "state dropped second", width: 100,
			want:       []string{"PROCESS", "LOCAL", "REMOTE", "PROTO", "PID", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: 12,
		},
		{
			name: "proto dropped third", width: 92,
			want:       []string{"PROCESS", "LOCAL", "REMOTE", "PID", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: 12,
		},
		{
			name: "pid dropped fourth", width: 86,
			want:       []string{"PROCESS", "LOCAL", "REMOTE", "↓ RATE", "↑ RATE", "↓ TOTAL", "↑ TOTAL"},
			labelWidth: 12,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cols := fitColumns(tableColumns(aggregate.GroupNone, stubHostname), tc.width)

			if got := columnTitles(cols); strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("columns = %v, want %v", got, tc.want)
			}
			if got := cols[labelColumn].width; got != tc.labelWidth {
				t.Errorf("label width = %d, want %d", got, tc.labelWidth)
			}
			if w := tableWidth(cols); w != tc.width {
				t.Errorf("table width = %d, want %d", w, tc.width)
			}
		})
	}
}

func TestFilterRowsMatchesLabelsAndHostnames(t *testing.T) {
	rows := []aggregate.Row{
		{Key: "140.82.112.3", Label: "140.82.112.3", RemoteAddr: "140.82.112.3"},
		{Key: "10.0.0.5", Label: "10.0.0.5", RemoteAddr: "10.0.0.5"},
	}
	hostname := func(r aggregate.Row) string {
		if r.RemoteAddr == "140.82.112.3" {
			return "lb.github.com"
		}
		return r.RemoteAddr
	}

	tests := []struct {
		name  string
		query string
		want  []string
	}{
		{name: "empty keeps everything", query: "", want: []string{"140.82.112.3", "10.0.0.5"}},
		{name: "matches the label", query: "10.0.0", want: []string{"10.0.0.5"}},
		{
			// The name is what the user knows the host as, and on a narrow
			// terminal it is not even on screen to be read off and typed.
			name: "matches the hostname", query: "github", want: []string{"140.82.112.3"},
		},
		{name: "case insensitive", query: "GITHUB", want: []string{"140.82.112.3"}},
		{name: "matches neither", query: "nothing", want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := filterRows(append([]aggregate.Row(nil), rows...), tc.query, hostname)

			labels := make([]string, len(got))
			for i, r := range got {
				labels[i] = r.Label
			}
			if strings.Join(labels, "|") != strings.Join(tc.want, "|") {
				t.Errorf("filterRows(%q) = %v, want %v", tc.query, labels, tc.want)
			}
		})
	}
}
