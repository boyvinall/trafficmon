package ui

import "github.com/charmbracelet/bubbles/key"

// KeyMap is the full key reference, per the plan's interaction spec.
type KeyMap struct {
	Up       key.Binding
	Down     key.Binding
	Mode     key.Binding
	Enter    key.Binding
	Back     key.Binding
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
		Mode:     key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "process/destination")),
		Enter:    key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "drill in")),
		Back:     key.NewBinding(key.WithKeys("esc", "backspace"), key.WithHelp("esc", "back")),
		Grouping: key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "ip / ip:port")),
		Sort:     key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "sort")),
		RateSort: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "rate/total")),
		Filter:   key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		Pause:    key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "pause")),
		Help:     key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		Quit:     key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}

// ShortHelp implements help.KeyMap.
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Mode, k.Enter, k.Sort, k.Help, k.Quit}
}

// FullHelp implements help.KeyMap.
func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Enter, k.Back},
		{k.Mode, k.Grouping, k.Sort, k.RateSort},
		{k.Filter, k.Pause, k.Help, k.Quit},
	}
}
