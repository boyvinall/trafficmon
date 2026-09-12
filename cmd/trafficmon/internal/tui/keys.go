package tui

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

// KeyMap is the full key reference.
//
// Every binding the UI honours is declared here and nowhere else: Update
// matches against these bindings rather than raw key strings, and the footer
// and help overlay are rendered from the same values, so a key cannot be
// advertised without being wired up or rebound in only one of the two places.
type KeyMap struct {
	Up              key.Binding
	Down            key.Binding
	PageUp          key.Binding
	PageDown        key.Binding
	Home            key.Binding
	End             key.Binding
	Grouping        key.Binding
	Sort            key.Binding
	RateSort        key.Binding
	Filter          key.Binding
	ToggleListening key.Binding
	ToggleTCP       key.Binding
	ToggleUDP       key.Binding
	ToggleIPv4      key.Binding
	ToggleIPv6      key.Binding
	TogglePrivate   key.Binding
	Interfaces      key.Binding
	// FocusNext cycles which of the Connections/Events panels the keyboard
	// acts on. Zoom gives the focused panel the full height (border kept),
	// and Unzoom restores the split — the only way out while zoomed, since
	// FocusNext is a no-op in that state.
	FocusNext key.Binding
	Zoom      key.Binding
	Unzoom    key.Binding
	Pause     key.Binding
	Help      key.Binding
	Quit      key.Binding
}

// DefaultKeyMap returns the standard bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Up:              key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:            key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		PageUp:          key.NewBinding(key.WithKeys("pgup", "ctrl+b"), key.WithHelp("pgup", "page up")),
		PageDown:        key.NewBinding(key.WithKeys("pgdown", "ctrl+f"), key.WithHelp("pgdn", "page down")),
		Home:            key.NewBinding(key.WithKeys("home"), key.WithHelp("home", "top")),
		End:             key.NewBinding(key.WithKeys("end", "G"), key.WithHelp("end/G", "bottom")),
		Grouping:        key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "cycle grouping")),
		Sort:            key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "cycle sort")),
		RateSort:        key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "rate/total")),
		Filter:          key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		ToggleListening: key.NewBinding(key.WithKeys("l"), key.WithHelp("l", "toggle listening")),
		ToggleTCP:       key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "toggle tcp")),
		ToggleUDP:       key.NewBinding(key.WithKeys("u"), key.WithHelp("u", "toggle udp")),
		ToggleIPv4:      key.NewBinding(key.WithKeys("4"), key.WithHelp("4", "toggle ipv4")),
		ToggleIPv6:      key.NewBinding(key.WithKeys("6"), key.WithHelp("6", "toggle ipv6")),
		TogglePrivate:   key.NewBinding(key.WithKeys("P"), key.WithHelp("P", "toggle private")),
		Interfaces:      key.NewBinding(key.WithKeys("i"), key.WithHelp("i", "toggle interfaces")),
		FocusNext:       key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "switch panel")),
		Zoom:            key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "zoom panel")),
		Unzoom:          key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "unzoom")),
		Pause:           key.NewBinding(key.WithKeys("p", " "), key.WithHelp("p/space", "pause")),
		Help:            key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		Quit:            key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}

// ShortHelp implements help.KeyMap.
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Grouping, k.Sort, k.Interfaces, k.Help, k.Quit}
}

// FullHelp implements help.KeyMap. Each inner slice is one column of the `?`
// overlay, grouped by what the keys do: moving the selection, changing what
// the table shows, and running the session.
//
// Three columns rather than four is a width decision as much as a grouping
// one: the help bubble drops a whole column when the overlay will not fit, and
// the narrower the columns are, the more terminals see every key.
func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.PageUp, k.PageDown, k.Home, k.End},
		{k.Filter, k.ToggleListening, k.ToggleTCP, k.ToggleUDP, k.ToggleIPv4, k.ToggleIPv6, k.TogglePrivate, k.Interfaces},
		{k.Grouping, k.Sort, k.RateSort, k.FocusNext, k.Zoom, k.Unzoom, k.Pause, k.Help, k.Quit},
	}
}

// handleKey applies one keypress.
//
// Keys are matched against the KeyMap rather than compared as strings, so the
// bindings the footer and the help overlay advertise are by construction the
// bindings that act — rebinding a key in one place cannot leave the other
// describing the old one.
func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// While the filter input has the keyboard, a keypress is text and nothing
	// else. Nearly every binding below is a bare letter, so honouring them
	// during an edit would have "q" quit and "p" pause in the middle of a
	// word; the input is claimed first rather than fallen through to.
	if m.filtering {
		return m.handleFilterKey(msg)
	}

	// While the help overlay has the screen, it claims the keyboard the same
	// way: everything a normal keypress would act on — the cursor, grouping,
	// the filter — is out of sight underneath it, so only leaving the program
	// or closing the overlay make sense. Esc is handled as a raw key type
	// rather than through the KeyMap, the same way the filter input handles
	// it: there is nothing left for it to mean at the table level.
	if m.showHelp {
		switch {
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.keys.Help), msg.Type == tea.KeyEsc:
			m.showHelp = false
		}
		return m, nil
	}

	// The interface picker claims the keyboard the same way, for the same
	// reason: everything underneath it is out of sight, so only leaving the
	// program, closing the picker, or acting on the picker itself make sense.
	if m.showIfacePicker {
		return m.handleIfacePickerKey(msg)
	}

	// Esc only means anything while a panel is zoomed — everything else
	// below applies to whichever panel has focus regardless of zoom, since
	// zoom only changes layout, not input routing.
	if m.zoomed && key.Matches(msg, m.keys.Unzoom) {
		m.zoomed = false
		return m, nil
	}

	return m.handleTableKey(msg)
}

// handleTableKey applies one keypress once none of handleKey's overlays
// (filter input, help, interface picker) claim the keyboard first.
func (m Model) handleTableKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit

	case key.Matches(msg, m.keys.Up):
		m.moveSelection(-1)
	case key.Matches(msg, m.keys.Down):
		m.moveSelection(1)
	case key.Matches(msg, m.keys.PageUp):
		m.moveSelection(-m.pageSize())
	case key.Matches(msg, m.keys.PageDown):
		m.moveSelection(m.pageSize())
	case key.Matches(msg, m.keys.Home):
		m.moveSelection(-m.selectionLen())
	case key.Matches(msg, m.keys.End):
		m.moveSelection(m.selectionLen())

	case key.Matches(msg, m.keys.FocusNext):
		if !m.zoomed {
			m.toggleFocus()
		}
	case key.Matches(msg, m.keys.Zoom):
		m.zoomed = true

	case key.Matches(msg, m.keys.Grouping):
		m.cycleGrouping()

	// `s` walks the whole cycle and `r` jumps straight between the two
	// bandwidth sorts; both land on the same SortKey, so whichever the user
	// reaches for, the other stays consistent with it.
	case key.Matches(msg, m.keys.Sort):
		m.setSort(m.sort.next())
	case key.Matches(msg, m.keys.RateSort):
		m.setSort(m.sort.toggleRate())

	case key.Matches(msg, m.keys.Filter):
		return m, m.openFilter()

	case key.Matches(msg, m.keys.ToggleListening):
		m.toggleListening()
	case key.Matches(msg, m.keys.ToggleTCP):
		m.toggleTCP()
	case key.Matches(msg, m.keys.ToggleUDP):
		m.toggleUDP()
	case key.Matches(msg, m.keys.ToggleIPv4):
		m.toggleIPv4()
	case key.Matches(msg, m.keys.ToggleIPv6):
		m.toggleIPv6()
	case key.Matches(msg, m.keys.TogglePrivate):
		m.togglePrivate()

	case key.Matches(msg, m.keys.Pause):
		m.paused = !m.paused
	case key.Matches(msg, m.keys.Help):
		m.showHelp = !m.showHelp
	case key.Matches(msg, m.keys.Interfaces):
		m.showIfacePicker = !m.showIfacePicker
	}
	return m, nil
}

// handleIfacePickerKey applies one keypress while the interface picker has
// the screen: Up/Down move the highlighted interface, space/enter flip it,
// and everything else that isn't leaving the program or closing the picker
// is ignored, the same claim on the keyboard the help overlay makes above.
func (m Model) handleIfacePickerKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit
	case key.Matches(msg, m.keys.Interfaces), msg.Type == tea.KeyEsc:
		m.showIfacePicker = false
	case key.Matches(msg, m.keys.Up):
		m.moveIfaceCursor(-1)
	case key.Matches(msg, m.keys.Down):
		m.moveIfaceCursor(1)
	case msg.Type == tea.KeySpace, msg.Type == tea.KeyEnter:
		m.toggleActiveInterface()
	}
	return m, nil
}

// handleFilterKey applies one keypress while the filter input is open.
//
// The three keys it intercepts are matched on the key type rather than through
// the KeyMap, because in this context they do not mean what the KeyMap says
// they do. Enter is the drill key and esc pops the drill stack, yet here they
// have to commit and cancel the edit — milestone 6 left esc unclaimed at depth
// 0 for exactly this — and esc's other key, backspace, must stay a text edit
// rather than becoming a second way out. Reusing the bindings would therefore
// mean either drilling on commit or deleting a character on cancel.
//
// Ctrl-C is the exception that proves it: it is the terminal's own interrupt
// rather than a letter anyone types into a filter, and a text field that
// swallowed it would leave the user with no way out of the program at all.
func (m Model) handleFilterKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyEsc:
		m.cancelFilter()
		return m, nil
	case tea.KeyEnter:
		m.commitFilter()
		return m, nil
	default:
		// Every other key is ordinary text input, handled below.
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)

	// The table narrows as the user types rather than on commit: an
	// incremental filter is how the user finds out whether what they have
	// typed so far picks out the row they are after, and it is what gives esc
	// something to undo.
	m.filter = m.input.Value()
	m.rebuild()
	return m, cmd
}

// openFilter hands the keyboard to the filter input.
//
// It starts empty rather than pre-filled with the filter in force, so that the
// commonest thing to do next — type a new filter — needs no clearing first,
// and so that committing an empty input is a plain, discoverable way to take a
// filter off again.
func (m *Model) openFilter() tea.Cmd {
	m.filterBefore = m.filter
	m.filtering = true

	m.input.SetValue("")

	// Focus's returned command starts the cursor blinking, which the static
	// cursor NewModel configures never needs in practice — but it is threaded
	// back to the caller anyway rather than assumed nil, so a future change to
	// that configuration cannot silently drop a command Bubble Tea expects.
	cmd := m.input.Focus()

	m.filter = ""
	m.rebuild()
	return cmd
}

// commitFilter accepts what was typed and returns the keyboard to the table.
// The filter itself is already in force, having been applied keystroke by
// keystroke.
func (m *Model) commitFilter() {
	m.filtering = false
	m.input.Blur()
}

// cancelFilter abandons the edit and puts back the filter it was opened over.
func (m *Model) cancelFilter() {
	m.filtering = false
	m.input.Blur()

	m.filter = m.filterBefore
	m.rebuild()
}
