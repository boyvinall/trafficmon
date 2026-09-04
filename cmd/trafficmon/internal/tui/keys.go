package tui

import "github.com/charmbracelet/bubbles/key"

// KeyMap is the full key reference, per the plan's interaction spec.
//
// Every binding the UI honours is declared here and nowhere else: Update
// matches against these bindings rather than raw key strings, and the footer
// and help overlay are rendered from the same values, so a key cannot be
// advertised without being wired up or rebound in only one of the two places.
type KeyMap struct {
	Up       key.Binding
	Down     key.Binding
	PageUp   key.Binding
	PageDown key.Binding
	Home     key.Binding
	End      key.Binding
	Grouping key.Binding
	Sort     key.Binding
	RateSort key.Binding
	Filter   key.Binding
	Pause    key.Binding
	Help     key.Binding
	Quit     key.Binding
}

// DefaultKeyMap returns the standard bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Up:       key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:     key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		PageUp:   key.NewBinding(key.WithKeys("pgup", "ctrl+b"), key.WithHelp("pgup", "page up")),
		PageDown: key.NewBinding(key.WithKeys("pgdown", "ctrl+f"), key.WithHelp("pgdn", "page down")),
		Home:     key.NewBinding(key.WithKeys("home"), key.WithHelp("home", "top")),
		End:      key.NewBinding(key.WithKeys("end", "G"), key.WithHelp("end/G", "bottom")),
		Grouping: key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "cycle grouping")),
		Sort:     key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "cycle sort")),
		RateSort: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "rate/total")),
		Filter:   key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		Pause:    key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "pause")),
		Help:     key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		Quit:     key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}

// ShortHelp implements help.KeyMap.
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Grouping, k.Sort, k.Help, k.Quit}
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
		{k.Grouping, k.Sort, k.RateSort, k.Filter},
		{k.Pause, k.Help, k.Quit},
	}
}
