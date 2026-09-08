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

// Event kinds. The four capture-only streams Snapshot carries.
const (
	eventSYN eventKind = iota
	eventRST
	eventDNSQuery
	eventDNSError
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
	default:
		return "SYN"
	}
}

// eventRecord is one row in the events panel, formatted for display rather
// than carrying the raw capture/dpi types: the four source streams
// (capture.SYNEvent, capture.RSTEvent, dpi.QueryFinding,
// dpi.DNSErrorFinding) have no shared shape of their own.
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

// appendEvents converts snap's four capture-only event streams into
// eventRecords, merges them into one time-sorted list (capture drains each
// stream independently, so they arrive in four separately-ordered slices),
// and pushes them onto the model's own history — the one place they survive,
// since Snapshot itself drops them on the very next Refresh.
func (m *Model) appendEvents(snap aggregate.Snapshot) {
	recs := make([]eventRecord, 0, len(snap.SYNEvents)+len(snap.RSTEvents)+len(snap.DNSQueries)+len(snap.DNSErrors))

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

	sort.SliceStable(recs, func(i, j int) bool { return recs[i].At.Before(recs[j].At) })

	for _, rec := range recs {
		m.events.push(rec)
	}
}

// formatEventRow renders one eventRecord's TIME, TYPE, LOCAL, REMOTE and
// INFO columns as plain text, before padding — the same shape
// table.go's per-column cell functions take.
func formatEventRow(rec eventRecord) []string {
	return []string{
		rec.At.Format(eventTimeFormat),
		rec.Kind.String(),
		rec.Local,
		rec.Remote,
		rec.Info,
	}
}

// Column geometry for the events panel. TIME and TYPE are fixed to the
// widest value they ever hold; LOCAL/REMOTE are generous enough for a
// bracketed IPv6 addr:port; INFO takes whatever width is left over.
const (
	eventTimeFormat = "15:04:05"
	eventTimeWidth  = 8  // len(eventTimeFormat's output)
	eventTypeWidth  = 7  // "DNS ERR", the widest eventKind.String()
	eventAddrWidth  = 21 // "[2001:db8::1234]:443" plus a little room
)

// eventInfoWidth is how wide the INFO column gets: whatever contentWidth
// leaves over once the other four columns and their gaps are accounted for,
// floored at minLabelWidth the same way table.go's flexible columns are.
func eventInfoWidth(contentWidth int) int {
	fixed := eventTimeWidth + eventTypeWidth + eventAddrWidth*2 + colGap*4
	return clamp(contentWidth-fixed, minLabelWidth, contentWidth)
}

// eventColumnTitles and eventColumnWidths line up positionally with
// formatEventRow's output.
var eventColumnTitles = []string{"TIME", "TYPE", "LOCAL", "REMOTE", "INFO"}

func eventColumnWidths(infoWidth int) []int {
	return []int{eventTimeWidth, eventTypeWidth, eventAddrWidth, eventAddrWidth, infoWidth}
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

// renderEventRow renders one eventRecord as plain, unstyled text of exactly
// the events panel's row width.
func renderEventRow(rec eventRecord, infoWidth int) string {
	cells := formatEventRow(rec)
	widths := eventColumnWidths(infoWidth)
	for i, w := range widths {
		cells[i] = pad(cells[i], w, alignLeft, false)
	}
	return strings.Join(cells, strings.Repeat(" ", colGap))
}

// emptyEventsMessage stands in for the events panel body before any
// SYN/RST/DNS activity has been seen.
const emptyEventsMessage = "  (no events yet)"

// viewEvents renders the events panel's column header and as many rows as
// fit, keeping eventsCursor on screen and highlighting the selected row only
// while the events panel itself has focus — an unfocused panel's cursor
// should not visually compete with the focused panel's own selection.
func (m Model) viewEvents() []string {
	infoWidth := eventInfoWidth(m.contentWidth())
	lines := []string{m.styles.ColumnHeader.Render(renderEventHeader(infoWidth))}

	items := m.events.slice()
	if len(items) == 0 {
		lines = append(lines, m.styles.Breadcrumb.Render(emptyEventsMessage))
		return m.fitEvents(lines)
	}

	start, end := visibleWindow(len(items), m.eventsCursor, m.eventsRowLines())
	for i, rec := range items[start:end] {
		line := renderEventRow(rec, infoWidth)
		if start+i == m.eventsCursor && m.focus == focusEvents {
			line = m.styles.Selected.Render(line)
		}
		lines = append(lines, line)
	}
	return m.fitEvents(lines)
}

// fitEvents is fit's counterpart for the events panel, padding or trimming
// to exactly the rows eventsRowLines budgets.
func (m Model) fitEvents(lines []string) []string {
	return fitLines(lines, m.eventsRowLines())
}
