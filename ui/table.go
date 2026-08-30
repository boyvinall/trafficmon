package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/boyvinall/mac-nethogs/aggregate"
)

// SortKey is the column driving row order, cycled with `s`.
type SortKey uint8

// Sort keys, in cycle order.
const (
	SortRate SortKey = iota
	SortTotal
	SortConnections

	// numSortKeys bounds the `s` cycle, so a new key only has to be added
	// above. It must stay last.
	numSortKeys
)

// next returns the key `s` cycles to, wrapping back round to the rate sort.
func (k SortKey) next() SortKey { return (k + 1) % numSortKeys }

// toggleRate returns the key `r` jumps to.
//
// The plan gives `r` the narrower job of choosing which of the two bandwidth
// numbers drives the order, so it flips between rate and total and treats the
// connection-count sort — which is neither — as "not one of mine", landing on
// rate. `s` remains the way to reach every key in turn.
func (k SortKey) toggleRate() SortKey {
	if k == SortRate {
		return SortTotal
	}
	return SortRate
}

// String names the sort key for the header bar.
func (k SortKey) String() string {
	switch k {
	case SortTotal:
		return "total"
	case SortConnections:
		return "connections"
	default:
		return "rate"
	}
}

// sortRows orders rows by the active sort key, descending.
func sortRows(rows []aggregate.Row, k SortKey) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch k {
		case SortTotal:
			return a.BytesInTotal+a.BytesOutTotal > b.BytesInTotal+b.BytesOutTotal
		case SortConnections:
			return a.Connections > b.Connections
		default: // SortRate
			return a.RateInBps+a.RateOutBps > b.RateInBps+b.RateOutBps
		}
	})
}

// filterRows keeps only the rows whose label contains q, case-insensitively.
// An empty query keeps everything.
func filterRows(rows []aggregate.Row, q string) []aggregate.Row {
	if q == "" {
		return rows
	}

	q = strings.ToLower(q)
	out := rows[:0]
	for _, r := range rows {
		if strings.Contains(strings.ToLower(r.Label), q) {
			out = append(out, r)
		}
	}
	return out
}

// alignment is which side of its cell a column's text sits on.
type alignment uint8

// Cell alignments. Numeric columns are right-aligned so that digits, units and
// the decimal point line up down the column; the label is left-aligned.
const (
	alignLeft alignment = iota
	alignRight
)

// Column drop priorities, lowest dropped first when the terminal is too narrow
// to show everything.
//
// prioEssential marks a column that is never dropped. The label and all four
// rate/total columns are essential: the plan is explicit that live rate and
// cumulative total are shown side by side at all times rather than toggled
// between, so neither half may be traded away for width.
const (
	prioConnections = iota
	prioPID
	prioEssential
)

// Table geometry. The numeric widths are the widest value each formatter can
// produce, so a column never has to truncate a number: humanBytes tops out at
// "1024.0 KB" (9 cells) and humanRate at "1024.0 KB/s" (11).
const (
	colGap        = 2
	minLabelWidth = 10
	rateWidth     = 11
	totalWidth    = 9
	pidWidth      = 6
	connWidth     = 5

	// defaultWidth stands in for the terminal width until the first
	// tea.WindowSizeMsg arrives, so the very first frame is not rendered at
	// the minimum size.
	defaultWidth = 100

	// labelColumn is the index of the flexible label column. It is always
	// first, and it is the only column whose width is computed rather than
	// fixed.
	labelColumn = 0
)

// sortMarker flags the column titles the active sort key reads. Rows are
// always ordered largest first, so a downward-pointing mark doubles as the
// direction indicator.
const sortMarker = "▾"

// column describes one table column: its title, how wide it is, and how to
// pull its value out of a row.
//
// The cell function returns plain text. Styling is applied to a whole rendered
// line by the caller rather than per cell, which keeps the dimmed and selected
// variants of a row exactly as wide as a plain one.
type column struct {
	title string
	width int
	align alignment
	prio  int
	cell  func(aggregate.Row) string

	// sortable says whether sortKey below means anything, and sortKey is the
	// sort key this column's numbers feed. Marking those columns in the header
	// is what tells the user why the rows are in the order they are; the flag
	// is needed because the zero SortKey is a real key, so a column that
	// drives no ordering cannot say so by omission.
	//
	// A sort key can be spread over more than one column — the rate sort adds
	// both directions together — in which case every column it reads is
	// marked.
	sortable bool
	sortKey  SortKey
}

// tableColumns returns the column set for a view, in display order and before
// any narrow-terminal trimming.
//
// TODO(milestone 7): the by-destination view gains a HOSTNAME column from the
// async reverse resolver. It slots in immediately after the host column with a
// priority below prioConnections — it is the first thing to go when space runs
// short, because the IP it annotates is still on screen — and takes its width
// from the label column's flexible share, which is why that share is computed
// last rather than baked into a constant.
func tableColumns(mode Mode, g aggregate.Grouping) []column {
	cols := []column{{
		title: "PROCESS",
		align: alignLeft,
		prio:  prioEssential,
		cell:  func(r aggregate.Row) string { return r.Label },
	}}

	switch mode {
	case ModeProcess:
		// The PID only means anything in the by-process rollup; ByDestination
		// leaves it zero, so showing it there would be actively misleading.
		cols = append(cols, column{
			title: "PID",
			width: pidWidth,
			align: alignRight,
			prio:  prioPID,
			cell:  func(r aggregate.Row) string { return strconv.Itoa(int(r.PID)) },
		})
	case ModeDestination:
		cols[labelColumn].title = "HOST"
		if g == aggregate.GroupByIPPort {
			cols[labelColumn].title = "HOST:PORT"
		}
	}

	return append(cols,
		column{
			title:    "↓ RATE",
			width:    rateWidth,
			align:    alignRight,
			prio:     prioEssential,
			cell:     func(r aggregate.Row) string { return humanRate(r.RateInBps) },
			sortable: true,
			sortKey:  SortRate,
		},
		column{
			title:    "↑ RATE",
			width:    rateWidth,
			align:    alignRight,
			prio:     prioEssential,
			cell:     func(r aggregate.Row) string { return humanRate(r.RateOutBps) },
			sortable: true,
			sortKey:  SortRate,
		},
		column{
			title:    "↓ TOTAL",
			width:    totalWidth,
			align:    alignRight,
			prio:     prioEssential,
			cell:     func(r aggregate.Row) string { return humanBytes(r.BytesInTotal) },
			sortable: true,
			sortKey:  SortTotal,
		},
		column{
			title:    "↑ TOTAL",
			width:    totalWidth,
			align:    alignRight,
			prio:     prioEssential,
			cell:     func(r aggregate.Row) string { return humanBytes(r.BytesOutTotal) },
			sortable: true,
			sortKey:  SortTotal,
		},
		column{
			title:    "CONN",
			width:    connWidth,
			align:    alignRight,
			prio:     prioConnections,
			cell:     func(r aggregate.Row) string { return strconv.Itoa(r.Connections) },
			sortable: true,
			sortKey:  SortConnections,
		},
	)
}

// fitColumns trims cols to a terminal width and sizes the flexible label
// column from what the fixed-width columns leave behind.
//
// The policy, in order: hand the label every spare cell; once that would push
// it under minLabelWidth start dropping the lowest-priority column instead
// (connection count first, then PID); and if even the essential columns do not
// fit, stop dropping and render at the minimum width, letting the caller clip.
// Shrinking the label is preferred over dropping a column because a truncated
// process name is still recognisable, whereas a missing column is invisible.
func fitColumns(cols []column, width int) []column {
	if width <= 0 {
		width = defaultWidth
	}

	// Copy so that a caller's column set — in practice the freshly built one
	// from tableColumns, but not necessarily — is never mutated.
	cols = append([]column(nil), cols...)

	for {
		fixed := (len(cols) - 1) * colGap
		for _, c := range cols {
			fixed += c.width
		}

		spare := width - fixed
		if spare >= minLabelWidth || !dropLowest(&cols) {
			cols[labelColumn].width = max(spare, minLabelWidth)
			return cols
		}
	}
}

// dropLowest removes the lowest-priority droppable column, reporting whether
// there was one left to drop.
func dropLowest(cols *[]column) bool {
	victim := -1
	for i, c := range *cols {
		if c.prio == prioEssential {
			continue
		}
		if victim < 0 || c.prio < (*cols)[victim].prio {
			victim = i
		}
	}
	if victim < 0 {
		return false
	}

	*cols = append((*cols)[:victim], (*cols)[victim+1:]...)
	return true
}

// tableWidth is the rendered width of a line produced from cols.
func tableWidth(cols []column) int {
	w := (len(cols) - 1) * colGap
	for _, c := range cols {
		w += c.width
	}
	return w
}

// tableHeader renders the column title row, marking the columns the active
// sort key reads.
//
// The marker is prefixed rather than appended, and carries no separating
// space, because the numeric columns are sized to the widest value they can
// hold: anything wider than one cell would push a title out of its column and
// have it truncated.
func tableHeader(cols []column, k SortKey) string {
	cells := make([]string, len(cols))
	for i, c := range cols {
		title := c.title
		if c.sortable && c.sortKey == k {
			title = sortMarker + title
		}
		cells[i] = pad(title, c.width, c.align)
	}
	return strings.Join(cells, strings.Repeat(" ", colGap))
}

// renderRow renders one aggregated row as plain, unstyled text of exactly
// tableWidth(cols) cells.
//
// Rate and cumulative total are always emitted side by side; the sort key only
// decides the order rows appear in, never which numbers are shown.
func renderRow(r aggregate.Row, cols []column) string {
	cells := make([]string, len(cols))
	for i, c := range cols {
		cells[i] = pad(c.cell(r), c.width, c.align)
	}
	return strings.Join(cells, strings.Repeat(" ", colGap))
}

// renderRows renders every row against the same column set, so the result is a
// block of equal-width lines.
func renderRows(rows []aggregate.Row, cols []column) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, renderRow(r, cols))
	}
	return out
}

// pad lays s into a cell of exactly w display cells, against the requested
// side, truncating first if it does not fit.
func pad(s string, w int, a alignment) string {
	s = truncate(s, w)

	gap := w - lipgloss.Width(s)
	if gap <= 0 {
		return s
	}
	if a == alignRight {
		return strings.Repeat(" ", gap) + s
	}
	return s + strings.Repeat(" ", gap)
}

// truncate shortens s to at most w display cells, marking the cut with an
// ellipsis.
//
// Over-long labels are truncated rather than wrapped because a wrapped cell
// would push every following row down by a line and break the alignment of the
// columns to its right.
func truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	if w == 1 {
		return "…"
	}

	// Measure rune by rune rather than slicing bytes: process names and IPv6
	// addresses are usually ASCII, but nothing guarantees it.
	var b strings.Builder
	used := 0
	for _, r := range s {
		rw := lipgloss.Width(string(r))
		if used+rw > w-1 {
			break
		}
		b.WriteRune(r)
		used += rw
	}
	return b.String() + "…"
}

// humanBytes formats a byte count for display, e.g. "128 MB".
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// humanRate formats a throughput for display, e.g. "2.1 MB/s".
func humanRate(bps float64) string {
	return humanBytes(uint64(bps)) + "/s"
}
