// Package ui implements the Bubble Tea front end.
package ui

import (
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/boyvinall/mac-nethogs/aggregate"
)

// TickInterval is the render cadence. It is deliberately independent of both
// the capture rate and the process poll rate.
const TickInterval = time.Second

// appName is the title shown at the left of the header bar.
const appName = "mac-nethogs"

// chromeLines is how many lines View spends on furniture rather than data: the
// header bar, the column titles and the footer.
const chromeLines = 3

// defaultPageSize is how far PgUp/PgDn move the cursor before the terminal
// height is known and a real screenful can be measured.
const defaultPageSize = 10

// emptyMessage stands in for the table body before any traffic has been seen,
// so a working but idle capture does not look like a broken one.
const emptyMessage = "  (no traffic yet)"

type tickMsg time.Time

// Model is the root Bubble Tea model.
type Model struct {
	agg    *aggregate.Aggregator
	iface  string
	keys   KeyMap
	styles Styles
	// help renders both the footer hint line and the `?` overlay from keys,
	// so the two can never drift apart from the bindings Update acts on.
	help help.Model

	stack    *Stack
	grouping aggregate.Grouping
	sort     SortKey

	// snap is the most recent aggregator snapshot, kept so that a change of
	// mode, grouping, sort or filter can rebuild the table from it on the very
	// next frame. Waiting for the next tick would leave the header describing
	// one view while the table still showed another, and while paused it would
	// never take effect at all.
	snap aggregate.Snapshot

	rows   []aggregate.Row
	cursor int
	// now is the timestamp of the most recent refresh. The view needs it to
	// decide which rows have gone quiet and should render dimmed; holding it
	// on the model rather than calling time.Now inside View keeps rendering a
	// pure function of the model, which is what makes it testable.
	now      time.Time
	paused   bool
	showHelp bool
	filter   string

	width, height int
}

// NewModel builds the root model.
func NewModel(agg *aggregate.Aggregator, iface string) Model {
	return Model{
		agg:    agg,
		iface:  iface,
		keys:   DefaultKeyMap(),
		styles: DefaultStyles(),
		help:   help.New(),
		stack:  NewStack(ModeProcess),
	}
}

// Init starts the render ticker.
func (m Model) Init() tea.Cmd {
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(TickInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Update handles input and tick messages.
//
// TODO(milestone 6): wire Enter/Esc onto the drill-down stack.
// TODO(milestone 7): make `/` open a text input rather than only clearing.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

	case tickMsg:
		// A paused model freezes its clock along with its rows: `now` is what
		// decides which rows render as closed, so letting it run on would have
		// a frozen table quietly grey itself out.
		if !m.paused {
			m.refresh(time.Time(msg))
		}
		return m, tick()

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// handleKey applies one keypress.
//
// Keys are matched against the KeyMap rather than compared as strings, so the
// bindings the footer and the help overlay advertise are by construction the
// bindings that act — rebinding a key in one place cannot leave the other
// describing the old one.
func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit

	case key.Matches(msg, m.keys.Up):
		m.moveCursor(-1)
	case key.Matches(msg, m.keys.Down):
		m.moveCursor(1)
	case key.Matches(msg, m.keys.PageUp):
		m.moveCursor(-m.pageSize())
	case key.Matches(msg, m.keys.PageDown):
		m.moveCursor(m.pageSize())
	case key.Matches(msg, m.keys.Home):
		m.moveCursor(-len(m.rows))
	case key.Matches(msg, m.keys.End):
		m.moveCursor(len(m.rows))

	case key.Matches(msg, m.keys.Mode):
		m.toggleMode()
	case key.Matches(msg, m.keys.Grouping):
		m.toggleGrouping()

	// `s` walks the whole cycle and `r` jumps straight between the two
	// bandwidth sorts the plan singles out; both land on the same SortKey, so
	// whichever the user reaches for, the other stays consistent with it.
	case key.Matches(msg, m.keys.Sort):
		m.setSort(m.sort.next())
	case key.Matches(msg, m.keys.RateSort):
		m.setSort(m.sort.toggleRate())

	case key.Matches(msg, m.keys.Filter):
		m.filter = ""
		m.rebuild()

	case key.Matches(msg, m.keys.Pause):
		m.paused = !m.paused
	case key.Matches(msg, m.keys.Help):
		m.showHelp = !m.showHelp
	}
	return m, nil
}

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

// pageSize is how far PgUp/PgDn move the cursor: one screenful, so that paging
// lines up with what the user can actually see. Until the first
// tea.WindowSizeMsg arrives there is no screenful to measure, so it falls back
// to a fixed jump.
func (m Model) pageSize() int {
	if n := m.rowLines(); n > 0 {
		return n
	}
	return defaultPageSize
}

// toggleMode swaps the top-level view between processes and destinations.
//
// It does nothing once the user has drilled in. Tab means "show me the other
// top-level view", and inside a drill-down the other view of the same scope is
// exactly what Enter already offers; silently unwinding the drill path on a
// key that normally does something small would throw away navigation the user
// did deliberately. Esc is the way back out, and footerKeys stops offering tab
// at depth so the key is not advertised where it has no effect.
func (m *Model) toggleMode() {
	if m.stack.Depth() > 0 {
		return
	}

	if m.stack.Top().Mode == ModeProcess {
		m.stack.SetMode(ModeDestination)
	} else {
		m.stack.SetMode(ModeProcess)
	}
	m.resetRows()
	m.rebuild()
}

// toggleGrouping switches the by-destination view between one row per remote
// IP and one per remote IP:port. The by-process view has no destinations to
// group, so there it is a no-op rather than a change that only shows up later.
func (m *Model) toggleGrouping() {
	if m.stack.Top().Mode != ModeDestination {
		return
	}

	if m.grouping == aggregate.GroupByIP {
		m.grouping = aggregate.GroupByIPPort
	} else {
		m.grouping = aggregate.GroupByIP
	}
	m.resetRows()
	m.rebuild()
}

// setSort changes the sort key and reorders what is already on screen, so the
// new order is visible on the next frame rather than at the next tick.
func (m *Model) setSort(k SortKey) {
	m.sort = k
	m.rebuild()
}

// refresh pulls a fresh snapshot from the aggregator and rebuilds the table
// from it.
func (m *Model) refresh(now time.Time) {
	m.snap = m.agg.Refresh(now)
	m.now = now
	m.rebuild()
}

// rebuild recomputes the visible rows from the snapshot the model already
// holds.
//
// It never asks the aggregator for fresh data: Refresh recomputes rates
// against a newer clock and ages rows out, which is precisely what pause
// exists to prevent, so a mode or sort change made while paused must be able
// to redraw the frozen data rather than thaw it.
//
// Taking the rows apart from where they came from is also what lets the parts
// with all the subtlety in them — the filter, the sort and the cursor — be
// exercised with hand-built inputs, no live capture and no root.
func (m *Model) rebuild() {
	snap := m.stack.Apply(m.snap)

	var rows []aggregate.Row
	switch m.stack.Top().Mode {
	case ModeProcess:
		rows = aggregate.ByProcess(snap)
	case ModeDestination:
		rows = aggregate.ByDestination(snap, m.grouping)
	}

	rows = filterRows(rows, m.filter)
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

// View renders the header bar, the table (or the help overlay in its place)
// and the footer as one frame no taller than the terminal.
func (m Model) View() string {
	lines := []string{m.viewHeader()}
	if m.showHelp {
		lines = append(lines, m.viewHelp()...)
	} else {
		lines = append(lines, m.viewTable()...)
	}
	lines = append(lines, m.viewFooter())

	// Nothing may be wider than the terminal, and the pieces cannot all
	// guarantee that themselves: the column layout has a floor it refuses to
	// shrink past, and the help bubble stops dropping columns while it is
	// still overflowing. Clipping here catches all of them in one place, and
	// it has to be done: an over-wide line wraps, and every wrapped line
	// pushes the footer further off the bottom of the screen.
	//
	// Only the lines that actually overflow are put through it: clipping
	// rewrites a line's styling cell by cell, which is a lot of escape
	// sequences to send every second for lines that already fit.
	clip := lipgloss.NewStyle().MaxWidth(m.viewWidth())
	for i, l := range lines {
		if lipgloss.Width(l) > m.viewWidth() {
			lines[i] = clip.Render(l)
		}
	}

	// A frame taller than the terminal would scroll the header off the top, so
	// clip rather than let that happen on a very short window.
	if m.height > 0 && len(lines) > m.height {
		lines = lines[:m.height]
	}
	return strings.Join(lines, "\n")
}

// viewHeader renders the title bar: the current mode and drill-down breadcrumb
// on the left, the capture interface and status pushed out to the right.
func (m Model) viewHeader() string {
	// The header style already pads a cell either side, so the segments hung
	// off it must not add a leading space of their own.
	left := m.styles.Header.Render(appName + " · " + modeLabel(m.stack.Top().Mode, m.grouping))
	if bc := m.stack.Breadcrumb(); bc != "" {
		left += m.styles.Breadcrumb.Render("› " + bc)
	}

	// The sort key is named here as well as marked on the column it reads,
	// because that column is one of the first to be dropped on a narrow
	// terminal and the row order would otherwise have no explanation at all.
	status := "sort: " + m.sort.String() + " · " + m.iface

	right := m.styles.Breadcrumb.Render(status + " · live")
	if m.paused {
		right = m.styles.Breadcrumb.Render(status+" ·") + m.styles.Paused.Render(" PAUSED ")
	}

	return joinEnds(left, right, m.viewWidth())
}

// viewTable renders the column titles and as many rows as fit, keeping the
// cursor on screen.
func (m Model) viewTable() []string {
	cols := fitColumns(tableColumns(m.stack.Top().Mode, m.grouping), m.viewWidth())
	lines := []string{m.styles.ColumnHeader.Render(tableHeader(cols, m.sort))}

	if len(m.rows) == 0 {
		lines = append(lines, m.styles.Breadcrumb.Render(emptyMessage))
		return m.fit(lines)
	}

	start, end := visibleWindow(len(m.rows), m.cursor, m.rowLines())
	for i, line := range renderRows(m.rows[start:end], cols) {
		row := m.rows[start+i]

		// Dim first, then invert: a closed row that also happens to be under
		// the cursor should still read as both.
		if row.Closed(m.now) {
			line = m.styles.Closed.Render(line)
		}
		if start+i == m.cursor {
			line = m.styles.Selected.Render(line)
		}
		lines = append(lines, line)
	}
	return m.fit(lines)
}

// viewHelp renders the full key reference in place of the table.
func (m Model) viewHelp() []string {
	h := m.help
	h.ShowAll = true
	h.Width = m.viewWidth()

	lines := []string{m.styles.ColumnHeader.Render("Key reference"), ""}
	lines = append(lines, strings.Split(h.FullHelpView(m.keys.FullHelp()), "\n")...)
	return m.fit(lines)
}

// viewFooter renders the context-sensitive key hints.
func (m Model) viewFooter() string {
	h := m.help
	h.ShowAll = false

	// The footer style pads a cell either side, which is width the hint line
	// itself cannot use.
	h.Width = max(m.viewWidth()-2, 1)

	return m.styles.Footer.Render(h.ShortHelpView(m.footerKeys()))
}

// footerKeys picks the hints for the current context: the standard set at the
// top level, and once the user has drilled in, the way back out in place of
// the top-level mode toggle. Esc does nothing at depth 0 and tab does nothing
// below it, so advertising either where it has no effect would be a lie.
func (m Model) footerKeys() []key.Binding {
	keys := m.keys.ShortHelp()
	if m.stack.Depth() == 0 {
		return keys
	}

	out := make([]key.Binding, 0, len(keys))
	for _, k := range keys {
		if k.Help() == m.keys.Mode.Help() {
			k = m.keys.Back
		}
		out = append(out, k)
	}
	return out
}

// fit pads or trims the body to exactly the number of lines the frame has room
// for, which is what pins the footer to the bottom of the terminal. A window
// whose size is not known yet gets the body unchanged.
func (m Model) fit(lines []string) []string {
	n := m.rowLines()
	if n <= 0 {
		return lines
	}

	// rowLines counts data rows; the column-title line sits above them.
	n++
	for len(lines) < n {
		lines = append(lines, "")
	}
	return lines[:n]
}

// rowLines is how many table rows the terminal has room for, or 0 when its
// height is not known yet and every row is drawn.
func (m Model) rowLines() int {
	if m.height <= 0 {
		return 0
	}
	return max(m.height-chromeLines, 1)
}

// viewWidth is the terminal width, falling back to a sensible default until
// the first tea.WindowSizeMsg arrives.
func (m Model) viewWidth() int {
	if m.width <= 0 {
		return defaultWidth
	}
	return m.width
}

// visibleWindow returns the half-open range of rows to draw so that the cursor
// stays on screen. A limit of zero or less means "no limit".
func visibleWindow(n, cursor, limit int) (start, end int) {
	if limit <= 0 || n <= limit {
		return 0, n
	}

	// Scroll only far enough to bring the cursor back into view, so the rows
	// around it stay put instead of the whole table jumping.
	start = 0
	if cursor >= limit {
		start = cursor - limit + 1
	}
	if start+limit > n {
		start = n - limit
	}
	return start, start + limit
}

// modeLabel names the current view for the header bar. The by-destination
// grouping is part of the name because it changes what a row means, and there
// is no other affordance telling the user which of the two is active.
func modeLabel(mode Mode, g aggregate.Grouping) string {
	if mode == ModeProcess {
		return "By Process"
	}
	if g == aggregate.GroupByIPPort {
		return "By Destination (ip:port)"
	}
	return "By Destination (ip)"
}

// joinEnds lays left at the start of a w-wide line and right at its end. If
// the two cannot both fit it keeps the left-hand segment, since wrapping would
// cost a line the table needs.
func joinEnds(left, right string, w int) string {
	gap := w - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		return left
	}
	return left + strings.Repeat(" ", gap) + right
}
