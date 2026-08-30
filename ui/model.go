// Package ui implements the Bubble Tea front end.
package ui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/boyvinall/mac-nethogs/aggregate"
)

// TickInterval is the render cadence. It is deliberately independent of both
// the capture rate and the process poll rate.
const TickInterval = time.Second

type tickMsg time.Time

// Model is the root Bubble Tea model.
type Model struct {
	agg    *aggregate.Aggregator
	iface  string
	keys   KeyMap
	styles Styles

	stack    *Stack
	grouping aggregate.Grouping
	sort     SortKey

	rows     []aggregate.Row
	cursor   int
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

	if m.cursor >= len(m.rows) {
		m.cursor = max(0, len(m.rows)-1)
	}
}

// View renders header, table and footer.
//
// TODO(milestone 4): render the real table, breadcrumb and context-sensitive
// footer hints.
func (m Model) View() string {
	header := m.styles.Header.Render("mac-nethogs — " + m.iface)
	if bc := m.stack.Breadcrumb(); bc != "" {
		header += " " + m.styles.Breadcrumb.Render(bc)
	}
	if m.paused {
		header += " " + m.styles.Breadcrumb.Render("[paused]")
	}

	body := ""
	for i, line := range renderRows(m.rows) {
		if i == m.cursor {
			line = m.styles.Selected.Render(line)
		}
		body += "\n" + line
	}

	return header + body + "\n" + m.styles.Footer.Render("tab mode · enter drill · s sort · p pause · ? help · q quit")
}
