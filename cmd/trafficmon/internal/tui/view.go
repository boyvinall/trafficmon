package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/lipgloss"
)

// View renders the header bar and the table (or the help overlay in its
// place) inside the Connections panel, the events feed inside the Events
// panel below it, and the footer below both, as one frame no taller than the
// terminal. While zoomed only the focused panel's own bordered box is drawn,
// per layout.
func (m Model) View() string {
	connRows, eventsRows := m.layout()

	var lines []string
	if connRows > 0 {
		lines = append(lines, m.viewConnPanel()...)
	}
	if eventsRows > 0 {
		lines = append(lines, m.viewEventsPanel()...)
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

// viewConnPanel renders the Connections panel: the header bar and the table
// (or the help overlay/interface picker in its place), inside a bordered box
// sized from rowLines/layout.
func (m Model) viewConnPanel() []string {
	body := []string{m.viewHeader()}
	switch {
	case m.showHelp:
		body = append(body, m.viewHelp()...)
	case m.showIfacePicker:
		body = append(body, m.viewIfacePicker()...)
	default:
		body = append(body, m.viewTable()...)
	}

	focused := m.zoomed || m.focus == focusConnections
	panel := renderPanel(m.styles, panelTitle, m.viewWidth(), len(body)+panelBorderHeight, strings.Join(body, "\n"), focused)
	return strings.Split(panel, "\n")
}

// viewEventsPanel renders the Events panel: the SYN/RST/DNS-query/DNS-error
// feed, inside a bordered box the same way viewConnPanel builds its own.
func (m Model) viewEventsPanel() []string {
	body := m.viewEvents()
	focused := m.zoomed || m.focus == focusEvents
	panel := renderPanel(m.styles, eventsPanelTitle, m.viewWidth(), len(body)+panelBorderHeight, strings.Join(body, "\n"), focused)
	return strings.Split(panel, "\n")
}

// viewHeader renders the title bar: the current grouping on the left, the
// sort/filter status and the toggle badges pushed out to the right.
func (m Model) viewHeader() string {
	// The header style already pads a cell either side, so the segments hung
	// off it must not add a leading space of their own.
	left := m.styles.Header.Render(appName + " · " + m.grouping.String())

	// The sort key is named here as well as marked on the column it reads,
	// because that column is one of the first to be dropped on a narrow
	// terminal and the row order would otherwise have no explanation at all.
	//
	// A filter in force is named alongside it for the same kind of reason,
	// and a stronger one: rows silently absent from the table look exactly
	// like traffic that stopped, and unlike the sort there is no mark
	// anywhere else on the screen to give it away.
	label := "sort: " + m.sort.String()
	if m.filter != "" {
		label = "filter: " + truncate(m.filter, maxFilterLabel) + " · " + label
	}
	status := m.styles.Header.Render(label)

	onOff := func(enable bool, on, off string) string {
		if enable {
			return m.styles.Live.Render(on)
		}
		return m.styles.Paused.Render(off)
	}

	right := strings.Join([]string{
		status,
		onOff(m.showListening, "LISTEN", "!LISTEN"),
		onOff(m.showTCP, "TCP", "!TCP"),
		onOff(m.showUDP, "UDP", "!UDP"),
		onOff(m.showIPv4, "IPV4", "!IPV4"),
		onOff(m.showIPv6, "IPV6", "!IPV6"),
		onOff(m.showPrivate, "PRIV", "!PRIV"),
		onOff(m.allInterfacesActive(), "IFACE", "!IFACE"),
		onOff(!m.paused, "live", "PAUSED"),
	}, " · ")

	return joinEnds(left, right, m.contentWidth())
}

// allInterfacesActive reports whether every known interface is currently
// shown, mirroring the LISTEN/TCP/UDP toggles' convention that true is the
// unfiltered state.
func (m Model) allInterfacesActive() bool {
	for _, name := range m.interfaces {
		if !m.activeInterfaces[name] {
			return false
		}
	}
	return true
}

// viewTable renders the column titles and as many rows as fit, keeping the
// cursor on screen.
func (m Model) viewTable() []string {
	cols := fitColumns(tableColumns(m.grouping, m.resolveHostname, m.now), m.contentWidth())
	lines := []string{m.styles.ColumnHeader.Render(tableHeader(cols, m.sort))}

	if len(m.rows) == 0 {
		lines = append(lines, m.styles.Breadcrumb.Render(m.emptyBody()))
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

// emptyBody explains a table with no rows in it. A filter is a likelier
// reason for one than an idle capture, and it has its own way out, so the two
// are worded separately rather than the filtered case claiming the capture
// has seen nothing.
func (m Model) emptyBody() string {
	if m.filter != "" {
		return emptyFilterMessage
	}
	return emptyMessage
}

// viewHelp renders the full key reference in place of the table.
func (m Model) viewHelp() []string {
	h := m.help
	h.ShowAll = true
	h.Width = m.contentWidth()

	helpLines := strings.Split(h.FullHelpView(m.keys.FullHelp()), "\n")
	lines := make([]string, 0, 2+len(helpLines))
	lines = append(lines, m.styles.ColumnHeader.Render("Key reference"), "")
	lines = append(lines, helpLines...)
	return m.fit(lines)
}

// viewIfacePicker renders the interface checklist in place of the table: one
// checkbox line per interface capture was started with, the highlighted one
// styled the same way the table's own selected row is.
func (m Model) viewIfacePicker() []string {
	lines := make([]string, 0, 2+len(m.interfaces))
	lines = append(lines, m.styles.ColumnHeader.Render("Interfaces"), "")

	for i, name := range m.interfaces {
		mark := "[ ]"
		if m.activeInterfaces[name] {
			mark = "[x]"
		}
		line := pad(mark+" "+name, m.contentWidth(), alignLeft, false)
		if i == m.ifaceCursor {
			line = m.styles.Selected.Render(line)
		}
		lines = append(lines, line)
	}
	return m.fit(lines)
}

// viewFooter renders the context-sensitive key hints, or the filter input in
// their place while one is being typed.
func (m Model) viewFooter() string {
	if m.filtering {
		return m.viewFilterInput()
	}

	h := m.help
	h.ShowAll = false

	// The footer style pads a cell either side, which is width the hint line
	// itself cannot use.
	h.Width = max(m.viewWidth()-2, 1)

	return m.styles.Footer.Render(h.ShortHelpView(m.footerKeys()))
}

// viewFilterInput renders the filter line the `/` key opens.
//
// It takes the footer's line rather than a line of its own: the footer is
// where the eye already goes to find out what can be pressed, the hints it
// displaces are precisely the ones that do not apply while the keyboard
// belongs to the input, and borrowing a line the frame already has costs the
// table no rows. When the typed filter grows long enough to reach the hint,
// joinEnds drops the hint rather than wrapping — by then it has been read.
func (m Model) viewFilterInput() string {
	// The footer style pads a cell either side, which is width the line
	// itself cannot use.
	w := max(m.viewWidth()-2, 1)
	return m.styles.Footer.Render(joinEnds(m.input.View(), filterHint, w))
}

// footerKeys picks the hints for the current context: the standard set,
// plus `/` once a filter is in force. It is the one state the user can put
// the table into that hides rows, so it is the one they may need to undo
// without having been told how; the rest of the time the footer is better
// spent on the keys that do something to what is on screen.
func (m Model) footerKeys() []key.Binding {
	keys := m.keys.ShortHelp()
	if m.filter == "" {
		return keys
	}

	out := make([]key.Binding, 0, len(keys)+1)
	for _, k := range keys {
		// Ahead of the help key, so the hints that change the table stay
		// together and the two that are about the session stay last.
		if k.Help() == m.keys.Help.Help() {
			out = append(out, m.keys.Filter)
		}
		out = append(out, k)
	}
	return out
}

// fit pads or trims the body to exactly the number of lines the frame has room
// for, which is what pins the footer to the bottom of the terminal. A window
// whose size is not known yet gets the body unchanged.
func (m Model) fit(lines []string) []string {
	return fitLines(lines, m.rowLines())
}

// fitLines is fit's underlying arithmetic, shared with fitEvents: n counts
// data rows, the column-title line sits above them, and n<=0 means the frame
// size is not known yet, so lines are returned unchanged.
func fitLines(lines []string, n int) []string {
	if n <= 0 {
		return lines
	}

	n++
	for len(lines) < n {
		lines = append(lines, "")
	}
	return lines[:n]
}

// rowLines is how many connections-table rows the terminal has room for, per
// layout, or 0 when the terminal size is not known yet and every row is
// drawn.
func (m Model) rowLines() int {
	connRows, _ := m.layout()
	return connRows
}

// viewWidth is the terminal width, falling back to a sensible default until
// the first tea.WindowSizeMsg arrives.
func (m Model) viewWidth() int {
	if m.width <= 0 {
		return defaultWidth
	}
	return m.width
}

// contentWidth is the width available to whatever renders inside the
// panel — the header line and the table — once renderPanel's own border and
// padding have taken their share of viewWidth.
func (m Model) contentWidth() int {
	return clamp(m.viewWidth()-panelBorderWidth, 1, m.viewWidth())
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
