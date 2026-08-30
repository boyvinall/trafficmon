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
// TODO(milestone 5): wire navigation and the mode/grouping toggles.
// TODO(milestone 6): wire Enter/Esc onto the drill-down stack.
// TODO(milestone 7): make `/` open a text input rather than only clearing.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

	case tickMsg:
		if !m.paused {
			m.refresh(time.Time(msg))
		}
		return m, tick()

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "p":
			m.paused = !m.paused
		case "?":
			m.showHelp = !m.showHelp
		case "s":
			m.sort = (m.sort + 1) % 3
		case "/":
			m.filter = ""
		}
	}
	return m, nil
}

// refresh recomputes the visible rows from a fresh aggregator snapshot.
func (m *Model) refresh(now time.Time) {
	snap := m.stack.Apply(m.agg.Refresh(now))

	switch m.stack.Top().Mode {
	case ModeProcess:
		m.rows = aggregate.ByProcess(snap)
	case ModeDestination:
		m.rows = aggregate.ByDestination(snap, m.grouping)
	}

	m.rows = filterRows(m.rows, m.filter)
	sortRows(m.rows, m.sort)
	m.now = now

	if m.cursor >= len(m.rows) {
		m.cursor = max(0, len(m.rows)-1)
	}
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

	right := m.styles.Breadcrumb.Render(m.iface + " · live")
	if m.paused {
		right = m.styles.Breadcrumb.Render(m.iface+" ·") + m.styles.Paused.Render(" PAUSED ")
	}

	return joinEnds(left, right, m.viewWidth())
}

// viewTable renders the column titles and as many rows as fit, keeping the
// cursor on screen.
func (m Model) viewTable() []string {
	cols := fitColumns(tableColumns(m.stack.Top().Mode, m.grouping), m.viewWidth())
	lines := []string{m.styles.ColumnHeader.Render(tableHeader(cols))}

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
// top level, plus the way back out once the user has drilled in. Esc does
// nothing at depth 0, so advertising it there would be a lie.
func (m Model) footerKeys() []key.Binding {
	keys := m.keys.ShortHelp()
	if m.stack.Depth() > 0 {
		keys = append(keys, m.keys.Back)
	}
	return keys
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
