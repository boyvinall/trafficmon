package tui

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/boyvinall/trafficmon/aggregate"
)

// SortKey is the column driving row order, cycled with `s`.
type SortKey uint8

// Sort keys, in cycle order.
const (
	SortRate SortKey = iota
	SortTotal
	SortPID

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
// PID sort — which is neither — as "not one of mine", landing on rate. `s`
// remains the way to reach every key in turn.
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
	case SortPID:
		return "pid"
	default:
		return "rate"
	}
}

// sortRows orders rows by the active sort key: rate and total descending,
// busiest first; PID ascending, lowest first, matching how every other tool
// that lists processes orders them.
func sortRows(rows []aggregate.Row, k SortKey) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch k {
		case SortTotal:
			return a.BytesInTotal+a.BytesOutTotal > b.BytesInTotal+b.BytesOutTotal
		case SortPID:
			return a.PID < b.PID
		default: // SortRate
			return a.RateInBps+a.RateOutBps > b.RateInBps+b.RateOutBps
		}
	})
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
// prioEssential marks a column that is never dropped. The label, LOCAL,
// REMOTE and all four rate/total columns are essential: they are the row's
// identity, and live rate and cumulative total are always shown side by side
// rather than toggled between, so none of them may be traded away for width.
//
// The hostname goes first of all, because it is the only column that annotates
// another one rather than carrying anything of its own: the address it names
// is still on screen without it. IFACE goes next — a genuinely new fact, but
// still supplementary the way HOSTNAME is — then STATE, then PROTO, then AGE,
// then CONN, then PID. AGE drops ahead of CONN and PID because it is purely
// supplementary — unlike CONN and PID it names nothing about the row's
// identity — but it is kept longer than HOSTNAME/IFACE/STATE/PROTO since it
// applies to every grouping alike.
const (
	prioHostname = iota
	prioIface
	prioState
	prioProto
	prioAge
	prioConnections
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
	// stateWidth fits "ESTABLISHED", the longest name tcpStateName returns.
	stateWidth = 11
	// protoWidth fits "PROTO", the column's own title — one cell wider than
	// "ICMP", the longest label protoLabel returns, so the header itself
	// never has to truncate.
	protoWidth = 5
	// ageWidth fits "999d23h", the longest string humanDuration returns.
	ageWidth = 7

	// dnsPort is the well-known port DNS runs over. It is not a wire
	// protocol of its own — procinfo and capture both only ever know this
	// traffic as tcp/udp — so protoLabel recognises it by port instead.
	dnsPort = 53

	// defaultWidth stands in for the terminal width until the first
	// tea.WindowSizeMsg arrives, so the very first frame is not rendered at
	// the minimum size.
	defaultWidth = 100

	// labelColumn is the index of the label column. It is always first, and it
	// is always one of the flexible columns whose width is computed rather
	// than fixed.
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

	// flex marks a column whose width is not fixed but shared out from
	// whatever the fixed-width columns leave over. The text in these columns —
	// a process name, an address, a hostname — has no bound on its length, so
	// there is no width that would be right at every terminal size.
	flex bool

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

	// truncLeft says this column overflowing its width should be truncated
	// from the front (truncateLeft) rather than the back (truncate). It is set
	// on PID and CONN: unlike rate/total, which humanRate/humanBytes keep
	// within their column by construction, these two numbers have no such
	// bound, and truncating a right-aligned number from the back would drop
	// its low-order digits — silently producing a different, plausible-looking
	// number rather than an obviously cut label.
	truncLeft bool
}

// tableColumns returns the column set for a grouping, in display order and
// before any narrow-terminal trimming.
//
// hostname supplies the reverse-resolved name annotating a row's remote
// address; it returns the bare address until one is known. Every grouping
// rolls up per remote endpoint, so a row always has one to name; hostname is
// nil only in tests that don't care about the HOSTNAME column.
//
// now is the frame's clock, passed through to ageColumn.
func tableColumns(g aggregate.Grouping, hostname func(aggregate.Row) string, now time.Time) []column {
	cols := []column{{
		title: "PROCESS",
		align: alignLeft,
		prio:  prioEssential,
		flex:  true,
		cell:  func(r aggregate.Row) string { return r.Label },
	}}

	switch g {
	case aggregate.GroupByPID:
		cols = append(cols, groupByPIDColumns(hostname)...)
	case aggregate.GroupByProcessName:
		cols = append(cols, groupByProcessNameColumns(hostname)...)
	default: // aggregate.GroupNone
		cols = append(cols, ungroupedColumns(hostname)...)
	}

	cols = append(cols, ageColumn(now))
	return append(cols, rateTotalColumns()...)
}

// groupByPIDColumns builds the columns specific to aggregate.GroupByPID: a
// row is exactly one process instance talking to exactly one remote
// endpoint here, so LOCAL, REMOTE and PID all still mean something; STATE
// does not, since the row can roll up more than one connection to that
// endpoint.
func groupByPIDColumns(hostname func(aggregate.Row) string) []column {
	cols := []column{
		localColumn(func(r aggregate.Row) string { return r.LocalAddr }),
		remoteColumn(),
	}
	if hostname != nil {
		cols = append(cols, hostnameColumn(hostname))
	}
	return append(cols, ifaceColumn(), pidColumn(), connColumn())
}

// groupByProcessNameColumns builds the columns specific to
// aggregate.GroupByProcessName: a process name can span several PIDs and
// local addresses, so nothing but the label, the remote endpoint and the
// connection count has one answer.
func groupByProcessNameColumns(hostname func(aggregate.Row) string) []column {
	cols := []column{remoteColumn()}
	if hostname != nil {
		cols = append(cols, hostnameColumn(hostname))
	}
	return append(cols, ifaceColumn(), connColumn())
}

// ungroupedColumns builds the columns specific to aggregate.GroupNone, where
// every field a single connection carries still means something.
func ungroupedColumns(hostname func(aggregate.Row) string) []column {
	cols := []column{
		localColumn(func(r aggregate.Row) string {
			return net.JoinHostPort(r.LocalAddr, strconv.Itoa(int(r.LocalPort)))
		}),
		remoteColumn(),
	}

	// The hostname sits immediately beside the address it names, and shares
	// the flexible width with it rather than taking a fixed slice: neither
	// an address nor a fully qualified name has a length worth baking into a
	// constant, and on a wide terminal both should grow.
	if hostname != nil {
		cols = append(cols, hostnameColumn(hostname))
	}

	return append(cols,
		ifaceColumn(),
		column{
			title: "PROTO",
			width: protoWidth,
			align: alignLeft,
			prio:  prioProto,
			cell:  protoLabel,
		},
		pidColumn(),
		column{
			title: "STATE",
			width: stateWidth,
			align: alignLeft,
			prio:  prioState,
			cell:  func(r aggregate.Row) string { return r.State },
		},
	)
}

// rateTotalColumns builds the four rate/total columns shared by every
// grouping — see prioEssential's doc comment for why these are never traded
// away for width.
func rateTotalColumns() []column {
	return []column{
		{
			title:    "↓ RATE",
			width:    rateWidth,
			align:    alignRight,
			prio:     prioEssential,
			cell:     func(r aggregate.Row) string { return humanRate(r.RateInBps) },
			sortable: true,
			sortKey:  SortRate,
		},
		{
			title:    "↑ RATE",
			width:    rateWidth,
			align:    alignRight,
			prio:     prioEssential,
			cell:     func(r aggregate.Row) string { return humanRate(r.RateOutBps) },
			sortable: true,
			sortKey:  SortRate,
		},
		{
			title:    "↓ TOTAL",
			width:    totalWidth,
			align:    alignRight,
			prio:     prioEssential,
			cell:     func(r aggregate.Row) string { return humanBytes(r.BytesInTotal) },
			sortable: true,
			sortKey:  SortTotal,
		},
		{
			title:    "↑ TOTAL",
			width:    totalWidth,
			align:    alignRight,
			prio:     prioEssential,
			cell:     func(r aggregate.Row) string { return humanBytes(r.BytesOutTotal) },
			sortable: true,
			sortKey:  SortTotal,
		},
	}
}

// localColumn builds the LOCAL column. cell differs by grouping: ungrouped it
// renders the full local addr:port, grouped by PID it renders the bare
// address (see aggregate.Row.LocalAddr's doc for why a grouped row only ever
// has one representative address to show). It is flexible, like REMOTE and
// PROCESS: an address has no length worth baking into a constant, and an
// IPv6 one truncated to a fixed width would be unreadable rather than merely
// short.
func localColumn(cell func(aggregate.Row) string) column {
	return column{title: "LOCAL", align: alignLeft, prio: prioEssential, flex: true, cell: cell}
}

// remoteColumn builds the REMOTE column, shared by every grouping: even
// GroupByPID and GroupByProcessName roll up per remote endpoint, so a row
// always has exactly one to show.
func remoteColumn() column {
	return column{
		title: "REMOTE",
		align: alignLeft,
		prio:  prioEssential,
		flex:  true,
		cell: func(r aggregate.Row) string {
			return net.JoinHostPort(r.RemoteAddr, strconv.Itoa(int(r.RemotePort)))
		},
	}
}

// hostnameColumn builds the HOSTNAME column, annotating whichever REMOTE
// column is in play. It sits immediately beside the address it names, and
// shares the flexible width with it rather than taking a fixed slice: neither
// an address nor a fully qualified name has a length worth baking into a
// constant, and on a wide terminal both should grow.
func hostnameColumn(hostname func(aggregate.Row) string) column {
	return column{title: "HOSTNAME", align: alignLeft, prio: prioHostname, flex: true, cell: hostname}
}

// ifaceColumn builds the IFACE column. Unlike PROTO/STATE, Row.Iface is
// carried through every grouping (see aggregate's rows.go), so this column
// is shared by all three, the same as REMOTE. It is flexible rather than a
// fixed width: short on Darwin/Linux ("en0", "eth0") but a raw libpcap NPF
// device path on Windows ("\Device\NPF_{GUID...}"), and nothing in this
// codebase resolves that to a friendlier adapter name.
func ifaceColumn() column {
	return column{title: "IFACE", align: alignLeft, prio: prioIface, flex: true, cell: func(r aggregate.Row) string { return r.Iface }}
}

// pidColumn builds the PID column, shared by the ungrouped and by-PID views —
// the only two where a row names exactly one process instance.
func pidColumn() column {
	return column{
		title: "PID",
		width: pidWidth,
		align: alignRight,
		prio:  prioPID,
		cell: func(r aggregate.Row) string {
			// PID 0 never occurs for a real socket; it marks a row synthesised
			// for a protocol with no owning process (ICMP, ARP).
			if r.PID == 0 {
				return "-"
			}
			return strconv.Itoa(int(r.PID))
		},
		sortable:  true,
		sortKey:   SortPID,
		truncLeft: true,
	}
}

// protoLabel returns the PROTO column's text for r: the transport protocol
// name, uppercased, or DNS when the traffic is UDP/TCP on the well-known DNS
// port — DNS is not a wire protocol of its own, so it is recognised by port
// rather than by r.Proto.
func protoLabel(r aggregate.Row) string {
	if (r.Proto == "tcp" || r.Proto == "udp") && (r.LocalPort == dnsPort || r.RemotePort == dnsPort) {
		return "DNS"
	}
	return strings.ToUpper(r.Proto)
}

// connColumn builds the CONN column, shown only once a grouping can roll more
// than one connection into a row — ungrouped, Connections is always 1 and the
// column would say nothing. It is display-only: sorting by connection count
// is exactly what left ties falling back to PID order feel like a hidden PID
// sort, so PID is now the explicit sort key instead (see pidColumn).
func connColumn() column {
	return column{
		title:     "CONN",
		width:     connWidth,
		align:     alignRight,
		prio:      prioConnections,
		cell:      func(r aggregate.Row) string { return strconv.Itoa(r.Connections) },
		truncLeft: true,
	}
}

// ageColumn builds the AGE column, shared by every grouping: how long ago the
// row's connection (or, grouped, the oldest of its rolled-up connections) was
// first observed. now is the frame's clock, threaded through rather than read
// live, for the same reason Model keeps its own now instead of calling
// time.Now() in View.
//
// A zero FirstSeen means the row's connections came from fixtures or tests
// that never went through Aggregator.join, rather than a real one seen for
// no time at all, so it renders as "-" rather than a huge, meaningless age.
func ageColumn(now time.Time) column {
	return column{
		title: "AGE",
		width: ageWidth,
		align: alignRight,
		prio:  prioAge,
		cell: func(r aggregate.Row) string {
			if r.FirstSeen.IsZero() {
				return "-"
			}
			return humanDuration(now.Sub(r.FirstSeen))
		},
	}
}

// fitColumns trims cols to a terminal width and sizes the flexible columns
// from what the fixed-width ones leave behind.
//
// The policy, in order: share every spare cell out between the flexible
// columns; once that would push one of them under minLabelWidth start dropping
// the lowest-priority column instead (hostname first, then connection count,
// then PID); and if even the essential columns do not fit, stop dropping and
// render at the minimum width, letting the caller clip. Shrinking the label is
// preferred over dropping a column because a truncated process name is still
// recognisable, whereas a missing column is invisible.
func fitColumns(cols []column, width int) []column {
	if width <= 0 {
		width = defaultWidth
	}

	// Copy so that a caller's column set — in practice the freshly built one
	// from tableColumns, but not necessarily — is never mutated.
	cols = append([]column(nil), cols...)

	for {
		fixed := (len(cols) - 1) * colGap
		flex := 0
		for _, c := range cols {
			fixed += c.width
			if c.flex {
				flex++
			}
		}

		spare := width - fixed
		if spare >= minLabelWidth*flex || !dropLowest(&cols) {
			shareFlex(cols, spare, flex)
			return cols
		}
	}
}

// shareFlex divides spare evenly between the flexible columns, never taking
// any of them below minLabelWidth.
//
// The odd cells go to the leftmost, which is the label: it carries the
// identity of the row, so if one of the two has to be a cell narrower it
// should not be that one.
func shareFlex(cols []column, spare, flex int) {
	if flex <= 0 {
		return
	}

	each := max(spare/flex, minLabelWidth)
	extra := spare - each*flex
	for i := range cols {
		if !cols[i].flex {
			continue
		}
		cols[i].width = each
		if extra > 0 {
			cols[i].width += extra
			extra = 0
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
		cells[i] = pad(title, c.width, c.align, c.truncLeft)
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
		cells[i] = pad(c.cell(r), c.width, c.align, c.truncLeft)
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
