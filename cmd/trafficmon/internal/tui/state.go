package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/boyvinall/trafficmon/aggregate"
)

// moveCursor moves the selection by delta rows, clamping at both ends.
//
// It deliberately does not wrap: rows reorder under the cursor as traffic
// moves, so wrapping would fling the user to the far end of a table that may
// have just changed shape — and nethogs does not wrap either.
func (m *Model) moveCursor(delta int) {
	if len(m.rows) == 0 {
		m.cursor = 0
		return
	}
	m.cursor = clamp(m.cursor+delta, 0, len(m.rows)-1)
}

// moveSelection moves whichever panel currently has focus's own cursor by
// delta: the connections table's cursor, or the events panel's eventsCursor.
// Zoom does not affect this routing — only which panels are drawn.
func (m *Model) moveSelection(delta int) {
	if m.focus == focusEvents {
		m.moveEventsCursor(delta)
		return
	}
	m.moveCursor(delta)
}

// moveEventsCursor moves the events panel's own cursor by delta, clamping at
// both ends the same way moveCursor does for the connections table, then
// brings eventsWindowTop along just far enough to keep the cursor visible.
func (m *Model) moveEventsCursor(delta int) {
	n := m.events.len()
	if n == 0 {
		m.eventsCursor = 0
		m.eventsWindowTop = 0
		return
	}
	m.eventsCursor = clamp(m.eventsCursor+delta, 0, n-1)
	m.eventsWindowTop = eventsWindowStart(m.eventsWindowTop, m.eventsCursor, n, m.eventsRowLines())
}

// selectionLen is how many rows the focused panel's cursor moves against —
// what Home/End clamp to.
func (m Model) selectionLen() int {
	if m.focus == focusEvents {
		return m.events.len()
	}
	return len(m.rows)
}

// toggleFocus swaps which of the two panels the keyboard acts on.
func (m *Model) toggleFocus() {
	if m.focus == focusConnections {
		m.focus = focusEvents
	} else {
		m.focus = focusConnections
	}
}

// moveIfaceCursor moves the interface picker's highlighted row by delta,
// clamping at both ends the same way moveCursor does for the table.
func (m *Model) moveIfaceCursor(delta int) {
	if len(m.interfaces) == 0 {
		m.ifaceCursor = 0
		return
	}
	m.ifaceCursor = clamp(m.ifaceCursor+delta, 0, len(m.interfaces)-1)
}

// toggleActiveInterface flips whether the highlighted interface's rows are
// shown, redrawing immediately rather than waiting for the next tick — the
// same immediacy toggleListening/toggleTCP/toggleUDP already have.
func (m *Model) toggleActiveInterface() {
	if m.ifaceCursor < 0 || m.ifaceCursor >= len(m.interfaces) {
		return
	}
	name := m.interfaces[m.ifaceCursor]
	m.activeInterfaces[name] = !m.activeInterfaces[name]
	m.rebuild()
}

// pageSize is how far PgUp/PgDn move the focused panel's cursor: one
// screenful of whichever panel that is, so that paging lines up with what
// the user can actually see. Until the first tea.WindowSizeMsg arrives there
// is no screenful to measure, so it falls back to a fixed jump.
func (m Model) pageSize() int {
	connRows, eventsRows := m.layout()
	n := connRows
	if m.focus == focusEvents {
		n = eventsRows
	}
	if n > 0 {
		return n
	}
	return defaultPageSize
}

// layout computes the data-row budget for the connections and events
// panels, given the terminal height, the zoom/focus state, and
// eventsPanelRows. It is the one place that arithmetic is spelled out, so
// that View's rendering and the mouse divider hit-test can never disagree.
//
// The footer always takes exactly one line, even while a panel is zoomed.
// While zoomed, the focused panel gets everything else and the other panel
// is not rendered at all (0 rows, no border drawn). Otherwise the events
// panel gets eventsPanelRows data rows (floored at minPanelDataRows) and
// connections gets whatever remains, floored the same way — trading away
// some of the events panel's rows first, since it is the one the user (or
// the default fraction) sized last.
func (m Model) layout() (connRows, eventsRows int) {
	if m.height <= 0 {
		return 0, 0
	}

	if m.zoomed {
		avail := m.splitTotalLines()
		if m.focus == focusEvents {
			return 0, max(avail-eventsChromeLines, 1)
		}
		return max(avail-connChromeLines, 1), 0
	}

	total := m.splitTotalLines()
	eventsRows = max(m.eventsPanelRows, minPanelDataRows)
	connRows = total - connChromeLines - (eventsRows + eventsChromeLines)
	if connRows < minPanelDataRows {
		connRows = minPanelDataRows
		eventsRows = max(total-connChromeLines-minPanelDataRows-eventsChromeLines, minPanelDataRows)
	}
	return connRows, eventsRows
}

// splitTotalLines is the total lines available to both panels' chrome and
// data combined: the terminal height minus the one line the footer always
// takes.
func (m Model) splitTotalLines() int {
	return max(m.height-1, 0)
}

// eventsRowLines is how many data rows the events panel currently has room
// for, per layout.
func (m Model) eventsRowLines() int {
	_, eventsRows := m.layout()
	return eventsRows
}

// resizePanels applies a new terminal size. eventsPanelRows is re-derived
// from the *fraction* of the two-panel area it occupied before the resize,
// rather than carried over as an absolute row count, so that a terminal
// resize does not leave the split's proportions stale; the very first resize
// has no prior fraction to preserve, so it seeds the eventsHeightFraction
// default instead.
func (m *Model) resizePanels(width, height int) {
	frac := 1.0 / float64(eventsHeightFraction)
	if m.eventsPanelRows > 0 {
		if prevTotal := m.splitTotalLines(); prevTotal > 0 {
			frac = float64(m.eventsPanelRows+eventsChromeLines) / float64(prevTotal)
		}
	}

	m.width, m.height = width, height

	total := m.splitTotalLines()
	m.eventsPanelRows = max(int(float64(total)*frac)-eventsChromeLines, minPanelDataRows)
}

// dividerRow is the terminal row of the line between the two panels — the
// connections panel's own bottom border — that a mouse press has to land on
// to start a divider drag. It returns -1 while zoomed, since there is no
// divider to grab: only one panel is ever on screen.
func (m Model) dividerRow() int {
	if m.zoomed {
		return -1
	}
	connRows, _ := m.layout()
	return connChromeLines + connRows - 1
}

// adjustEventsPanelRows grows or shrinks the events panel by delta data
// rows, clamped so neither panel can shrink below minPanelDataRows.
func (m *Model) adjustEventsPanelRows(delta int) {
	total := m.splitTotalLines()
	maxRows := max(total-connChromeLines-eventsChromeLines-minPanelDataRows, minPanelDataRows)
	m.eventsPanelRows = clamp(m.eventsPanelRows+delta, minPanelDataRows, maxRows)
}

// handleMouse applies one mouse event: pressing on the divider between the
// two panels starts a drag, motion while dragging resizes the events panel,
// and release ends it. Mouse input is ignored entirely while zoomed, since
// the divider it drags does not exist then.
func (m Model) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	if m.zoomed {
		return m, nil
	}

	switch msg.Action {
	case tea.MouseActionPress:
		if msg.Y == m.dividerRow() {
			m.draggingDivider = true
			m.dragRow = msg.Y
		}
	case tea.MouseActionMotion:
		if m.draggingDivider {
			delta := msg.Y - m.dragRow
			m.dragRow = msg.Y
			// Dragging the divider up (delta < 0) grows the events panel.
			m.adjustEventsPanelRows(-delta)
		}
	case tea.MouseActionRelease:
		m.draggingDivider = false
	}
	return m, nil
}

// cycleGrouping advances the grouping to the next of the three states —
// ungrouped, by PID, by process name — wrapping back round to ungrouped.
func (m *Model) cycleGrouping() {
	m.grouping = m.grouping.Next()
	m.resetRows()
	m.rebuild()
}

// setSort changes the sort key and reorders what is already on screen, so the
// new order is visible on the next frame rather than at the next tick.
func (m *Model) setSort(k SortKey) {
	m.sort = k
	m.rebuild()
}

// toggleListening flips whether LISTEN-state rows are shown, redrawing
// immediately rather than waiting for the next tick — the same immediacy
// grouping and sort changes get.
func (m *Model) toggleListening() {
	m.showListening = !m.showListening
	m.rebuild()
}

// toggleTCP flips whether TCP rows are shown, the same way toggleListening
// flips LISTEN rows.
func (m *Model) toggleTCP() {
	m.showTCP = !m.showTCP
	m.rebuild()
}

// toggleUDP flips whether UDP rows are shown, the same way toggleListening
// flips LISTEN rows.
func (m *Model) toggleUDP() {
	m.showUDP = !m.showUDP
	m.rebuild()
}

// toggleIPv4 flips whether IPv4 rows are shown, the same way toggleListening
// flips LISTEN rows.
func (m *Model) toggleIPv4() {
	m.showIPv4 = !m.showIPv4
	m.rebuild()
}

// toggleIPv6 flips whether IPv6 rows are shown, the same way toggleListening
// flips LISTEN rows.
func (m *Model) toggleIPv6() {
	m.showIPv6 = !m.showIPv6
	m.rebuild()
}

// togglePrivate flips whether rows with a private remote address are shown,
// the same way toggleListening flips LISTEN rows.
func (m *Model) togglePrivate() {
	m.showPrivate = !m.showPrivate
	m.rebuild()
}

// refresh pulls a fresh snapshot from the aggregator and rebuilds the table
// from it.
func (m *Model) refresh(now time.Time) {
	// Test fixtures routinely build a Model with no live aggregator behind it,
	// so a tick reaching one must do nothing rather than panic.
	if m.agg == nil {
		return
	}

	snap := m.agg.Refresh(now)
	// Copied out before m.snap is overwritten: Refresh drains these five
	// streams fresh every call and does not retain them (see Snapshot's own
	// doc comment), so this is the only chance to keep anything that
	// accumulated since the previous tick.
	m.appendEvents(snap)
	m.snap = snap
	m.now = now
	m.rebuild()
}

// rebuild recomputes the visible rows from the snapshot the model already
// holds.
//
// It never asks the aggregator for fresh data: Refresh recomputes rates
// against a newer clock and ages rows out, which is precisely what pause
// exists to prevent, so a grouping or sort change made while paused must be
// able to redraw the frozen data rather than thaw it.
//
// Taking the rows apart from where they came from is also what lets the parts
// with all the subtlety in them — the filter, the sort and the cursor — be
// exercised with hand-built inputs, no live capture and no root.
func (m *Model) rebuild() {
	rows := aggregate.Rows(m.snap, m.grouping)
	rows = filterListening(rows, m.showListening)
	rows = filterProto(rows, m.showTCP, m.showUDP)
	rows = filterIPFamily(rows, m.showIPv4, m.showIPv6)
	rows = filterPrivate(rows, m.showPrivate)
	rows = filterIface(rows, m.activeInterfaces)
	rows = filterRows(rows, m.filter, m.resolveHostname)
	sortRows(rows, m.sort)
	m.setRows(rows)
}

// setRows installs a freshly computed row set, keeping the cursor on the row
// it was already on.
func (m *Model) setRows(rows []aggregate.Row) {
	key := m.selectedKey()
	m.rows = rows
	m.cursor = cursorFor(rows, key, m.cursor)
}

// resetRows drops the rows on screen so that the next rebuild starts from the
// top. Changing mode or grouping changes what a row *is*, so there is no row
// left for the cursor to hold onto and keeping its index would land it
// somewhere arbitrary.
func (m *Model) resetRows() {
	m.rows, m.cursor = nil, 0
}

// selectedKey is the Key of the row under the cursor, or "" when there is no
// selection to preserve.
func (m Model) selectedKey() string {
	if m.cursor < 0 || m.cursor >= len(m.rows) {
		return ""
	}
	return m.rows[m.cursor].Key
}

// cursorFor finds where the row identified by key ended up in a freshly built
// row set.
//
// Rows reorder on nearly every refresh, so the cursor has to track the row the
// user selected rather than the position it happened to be in — otherwise the
// selection slides onto whatever row overtook it, and pressing enter opens
// something the user was not pointing at. A row that has aged out entirely has
// no new index to find, so the old position is the next best thing: the
// neighbours of a vanished row are what the user was looking at.
func cursorFor(rows []aggregate.Row, key string, fallback int) int {
	if len(rows) == 0 {
		return 0
	}
	if key != "" {
		for i, r := range rows {
			if r.Key == key {
				return i
			}
		}
	}
	return clamp(fallback, 0, len(rows)-1)
}

// clamp confines v to [lo, hi].
func clamp(v, lo, hi int) int {
	return min(max(v, lo), hi)
}
