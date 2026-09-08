package tui

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/boyvinall/trafficmon/aggregate"
)

// eventKind identifies what kind of capture-only event an eventRecord
// describes.
type eventKind uint8

// Event kinds. The five capture-only streams Snapshot carries.
const (
	eventSYN eventKind = iota
	eventRST
	eventDNSQuery
	eventDNSError
	eventDNSAnswer
)

// String names the event kind for the TYPE column.
func (k eventKind) String() string {
	switch k {
	case eventRST:
		return "RST"
	case eventDNSQuery:
		return "DNS Q"
	case eventDNSError:
		return "DNS ERR"
	case eventDNSAnswer:
		return "DNS A"
	default:
		return "SYN"
	}
}

// eventSeverity classifies an eventKind for display: RST and DNS-error rows
// signal a failure the user likely wants to notice, everything else is
// routine traffic.
type eventSeverity uint8

const (
	severityInfo eventSeverity = iota
	severityError
)

// severity reports k's eventSeverity. RST (an unexpected/refused connection)
// and DNS ERR (a failed lookup) are the only two failure-shaped streams
// Snapshot carries — SYN, DNS Q and DNS A are all just routine activity.
func (k eventKind) severity() eventSeverity {
	switch k {
	case eventRST, eventDNSError:
		return severityError
	default:
		return severityInfo
	}
}

// String names the severity for the LVL column.
func (s eventSeverity) String() string {
	if s == severityError {
		return "ERR"
	}
	return "INFO"
}

// eventRecord is one row in the events panel, formatted for display rather
// than carrying the raw capture/dpi types: the five source streams
// (capture.SYNEvent, capture.RSTEvent, dpi.QueryFinding,
// dpi.DNSErrorFinding, dpi.DNSAnswerFinding) have no shared shape of their
// own.
type eventRecord struct {
	At     time.Time
	Kind   eventKind
	Local  string // addr:port; blank for DNS rows, which have no local port
	Remote string
	Info   string
}

// eventRingCapacity bounds the events panel's own history, mirroring the
// drop-oldest ring buffers capture/synevents.go and capture/dns_queries.go
// already keep for these same streams, before Model's copy is the only place
// left holding them (see appendEvents).
const eventRingCapacity = 500

// eventRing is a fixed-capacity, drop-oldest queue of eventRecord values, in
// oldest-first order.
type eventRing struct {
	items []eventRecord
}

// push appends rec, dropping the oldest entry first once the ring is
// already at capacity.
func (r *eventRing) push(rec eventRecord) {
	if len(r.items) >= eventRingCapacity {
		copy(r.items, r.items[1:])
		r.items = r.items[:len(r.items)-1]
	}
	r.items = append(r.items, rec)
}

// slice returns the ring's contents, oldest first.
func (r *eventRing) slice() []eventRecord {
	return r.items
}

// len reports how many records the ring currently holds.
func (r *eventRing) len() int {
	return len(r.items)
}

// appendEvents converts snap's five capture-only event streams into
// eventRecords, merges them into one time-sorted list (capture drains each
// stream independently, so they arrive in five separately-ordered slices),
// and pushes them onto the model's own history — the one place they survive,
// since Snapshot itself drops them on the very next Refresh. If the events
// cursor was sitting on the most-recently-received record beforehand, it is
// carried forward onto whatever record ends up most recent afterwards, so
// the panel auto-scrolls along with a viewer who hasn't scrolled away from
// the live edge.
func (m *Model) appendEvents(snap aggregate.Snapshot) {
	followLatest := m.events.len() == 0 || m.eventsCursor == m.events.len()-1

	recs := make([]eventRecord, 0, len(snap.SYNEvents)+len(snap.RSTEvents)+len(snap.DNSQueries)+len(snap.DNSErrors)+len(snap.DNSAnswers))

	for _, e := range snap.SYNEvents {
		recs = append(recs, eventRecord{
			At:     e.At,
			Kind:   eventSYN,
			Local:  net.JoinHostPort(e.LocalAddr.String(), strconv.Itoa(int(e.LocalPort))),
			Remote: net.JoinHostPort(e.RemoteAddr.String(), strconv.Itoa(int(e.RemotePort))),
			Info:   e.Iface,
		})
	}
	for _, e := range snap.RSTEvents {
		recs = append(recs, eventRecord{
			At:     e.At,
			Kind:   eventRST,
			Local:  net.JoinHostPort(e.LocalAddr.String(), strconv.Itoa(int(e.LocalPort))),
			Remote: net.JoinHostPort(e.RemoteAddr.String(), strconv.Itoa(int(e.RemotePort))),
			Info:   e.Iface,
		})
	}
	for _, q := range snap.DNSQueries {
		recs = append(recs, eventRecord{
			At:     q.At,
			Kind:   eventDNSQuery,
			Local:  q.ClientAddr,
			Remote: q.ServerAddr,
			Info:   q.Name + " (" + q.QType + ")",
		})
	}
	for _, e := range snap.DNSErrors {
		recs = append(recs, eventRecord{
			At:     e.At,
			Kind:   eventDNSError,
			Remote: e.ServerAddr,
			Info:   e.Name + " (" + e.QType + ") " + e.RCode,
		})
	}
	for _, a := range snap.DNSAnswers {
		recs = append(recs, eventRecord{
			At:     a.At,
			Kind:   eventDNSAnswer,
			Remote: a.ServerAddr,
			Info:   a.Name + " (" + a.QType + ") -> " + a.Answer + " (ttl " + strconv.FormatUint(uint64(a.TTL), 10) + "s)",
		})
	}

	sort.SliceStable(recs, func(i, j int) bool { return recs[i].At.Before(recs[j].At) })

	for _, rec := range recs {
		m.events.push(rec)
	}

	if followLatest && m.events.len() > 0 {
		m.eventsCursor = m.events.len() - 1
	}
	m.eventsWindowTop = eventsWindowStart(m.eventsWindowTop, m.eventsCursor, m.events.len(), m.eventsRowLines())
}

// formatEventRow renders one eventRecord's TIME, LVL, TYPE, LOCAL, REMOTE and
// INFO columns as plain text, before padding — the same shape
// table.go's per-column cell functions take.
func formatEventRow(rec eventRecord) []string {
	return []string{
		rec.At.Format(eventTimeFormat),
		rec.Kind.severity().String(),
		rec.Kind.String(),
		rec.Local,
		rec.Remote,
		rec.Info,
	}
}

// eventSeverityColumn is formatEventRow/eventColumnWidths' index for the LVL
// column — the only cell renderEventRow colors by severity.
const eventSeverityColumn = 1

// Column geometry for the events panel. TIME, LVL and TYPE are fixed to the
// widest value they ever hold; LOCAL/REMOTE are generous enough for a
// bracketed IPv6 addr:port; INFO takes whatever width is left over.
const (
	eventTimeFormat    = "15:04:05"
	eventTimeWidth     = 8  // len(eventTimeFormat's output)
	eventSeverityWidth = 4  // "INFO", the widest eventSeverity.String()
	eventTypeWidth     = 7  // "DNS ERR", the widest eventKind.String()
	eventAddrWidth     = 21 // "[2001:db8::1234]:443" plus a little room
)

// eventInfoWidth is how wide the INFO column gets: whatever contentWidth
// leaves over once the other five columns and their gaps are accounted for,
// floored at minLabelWidth the same way table.go's flexible columns are.
func eventInfoWidth(contentWidth int) int {
	fixed := eventTimeWidth + eventSeverityWidth + eventTypeWidth + eventAddrWidth*2 + colGap*5
	return clamp(contentWidth-fixed, minLabelWidth, contentWidth)
}

// eventColumnTitles and eventColumnWidths line up positionally with
// formatEventRow's output.
var eventColumnTitles = []string{"TIME", "LVL", "TYPE", "LOCAL", "REMOTE", "INFO"}

func eventColumnWidths(infoWidth int) []int {
	return []int{eventTimeWidth, eventSeverityWidth, eventTypeWidth, eventAddrWidth, eventAddrWidth, infoWidth}
}

// renderEventHeader renders the events panel's column-title line.
func renderEventHeader(infoWidth int) string {
	widths := eventColumnWidths(infoWidth)
	cells := make([]string, len(eventColumnTitles))
	for i, title := range eventColumnTitles {
		cells[i] = pad(title, widths[i], alignLeft, false)
	}
	return strings.Join(cells, strings.Repeat(" ", colGap))
}

// renderEventRow renders one eventRecord at exactly the events panel's row
// width. Only the LVL cell carries any foreground color — green for INFO,
// red for ERR — so an otherwise-routine SYN/DNS-query/DNS-answer row and an
// error row (RST, DNS ERR) read the same everywhere except that one column.
//
// selected reproduces the cursor highlight per cell rather than wrapping the
// whole already-rendered line in styles.Selected the way the connections
// table does for a plain-text row: each styled cell's own trailing reset
// code would otherwise switch the outer Reverse back off for every cell
// after it, since SGR resets aren't scoped to the style that emitted
// them — they clear every attribute in effect on the terminal, including
// ones an enclosing style turned on before this string even started.
func renderEventRow(rec eventRecord, infoWidth int, styles Styles, selected bool) string {
	cells := formatEventRow(rec)
	widths := eventColumnWidths(infoWidth)
	for i, w := range widths {
		cells[i] = pad(cells[i], w, alignLeft, false)
	}

	lvlColor := styles.EventInfo
	if rec.Kind.severity() == severityError {
		lvlColor = styles.EventError
	}

	sep := strings.Repeat(" ", colGap)
	if !selected {
		cells[eventSeverityColumn] = lvlColor.Render(cells[eventSeverityColumn])
		return strings.Join(cells, sep)
	}

	lvlSelected := styles.Selected.Foreground(lvlColor.GetForeground())
	for i, cell := range cells {
		style := styles.Selected
		if i == eventSeverityColumn {
			style = lvlSelected
		}
		cells[i] = style.Render(cell)
	}
	return strings.Join(cells, styles.Selected.Render(sep))
}

// emptyEventsMessage stands in for the events panel body before any
// SYN/RST/DNS activity has been seen.
const emptyEventsMessage = "  (no events yet)"

// eventsWindowStart computes the events panel's own scroll-window start,
// scrolling by only as much as necessary to bring cursor back into a
// limit-row window beginning at prevStart — unlike visibleWindow, which
// re-anchors the cursor to whichever edge it crosses every time it is
// called, this lets the cursor move freely within an already-visible window,
// and lets appendEvents follow newly-arrived rows down without disturbing a
// window the user is deliberately holding in place. prevStart need not
// already be valid for n/limit — e.g. after a resize shrinks limit — since
// the two clamps below always bring it back into range first.
func eventsWindowStart(prevStart, cursor, n, limit int) int {
	if limit <= 0 || n <= limit {
		return 0
	}

	start := clamp(prevStart, 0, n-limit)
	if cursor < start {
		start = cursor
	}
	if cursor > start+limit-1 {
		start = cursor - limit + 1
	}
	return clamp(start, 0, n-limit)
}

// eventsVisibleWindow is eventsWindowStart's counterpart for rendering: it
// derives the same start (without persisting it — Model's View methods take
// a value receiver) plus the matching end index.
func eventsVisibleWindow(top, cursor, n, limit int) (start, end int) {
	if limit <= 0 || n <= limit {
		return 0, n
	}
	start = eventsWindowStart(top, cursor, n, limit)
	return start, start + limit
}

// viewEvents renders the events panel's column header and as many rows as
// fit, keeping eventsCursor on screen. The selected row is always
// highlighted, focus or not — matching the connections table, whose own
// cursor highlight isn't gated on focus either — so the panel's auto-scroll
// stays visible without the user needing to tab over to it first.
func (m Model) viewEvents() []string {
	infoWidth := eventInfoWidth(m.contentWidth())
	lines := []string{m.styles.ColumnHeader.Render(renderEventHeader(infoWidth))}

	items := m.events.slice()
	if len(items) == 0 {
		lines = append(lines, m.styles.Breadcrumb.Render(emptyEventsMessage))
		return m.fitEvents(lines)
	}

	start, end := eventsVisibleWindow(m.eventsWindowTop, m.eventsCursor, len(items), m.eventsRowLines())
	for i, rec := range items[start:end] {
		lines = append(lines, renderEventRow(rec, infoWidth, m.styles, start+i == m.eventsCursor))
	}
	return m.fitEvents(lines)
}

// fitEvents is fit's counterpart for the events panel, padding or trimming
// to exactly the rows eventsRowLines budgets.
func (m Model) fitEvents(lines []string) []string {
	return fitLines(lines, m.eventsRowLines())
}
