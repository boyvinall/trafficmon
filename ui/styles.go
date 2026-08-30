package ui

import "github.com/charmbracelet/lipgloss"

// Styles holds every lipgloss style the UI uses, so themes live in one place.
type Styles struct {
	Header     lipgloss.Style
	Breadcrumb lipgloss.Style
	Footer     lipgloss.Style
	Selected   lipgloss.Style
	// Closed dims rows whose connections have all gone away but are still
	// inside the grace period.
	Closed lipgloss.Style
	// ColumnHeader marks out the table's title row from the data beneath it.
	ColumnHeader lipgloss.Style
	// Paused flags frozen capture in the header bar. It is deliberately louder
	// than the rest of the bar: a paused table looks exactly like a live one
	// that has gone quiet, so the indicator is the only thing telling the two
	// apart.
	Paused lipgloss.Style
}

// DefaultStyles returns the standard theme.
func DefaultStyles() Styles {
	return Styles{
		Header:       lipgloss.NewStyle().Bold(true).Padding(0, 1),
		Breadcrumb:   lipgloss.NewStyle().Faint(true),
		Footer:       lipgloss.NewStyle().Faint(true).Padding(0, 1),
		Selected:     lipgloss.NewStyle().Reverse(true),
		Closed:       lipgloss.NewStyle().Faint(true),
		ColumnHeader: lipgloss.NewStyle().Bold(true).Underline(true),
		Paused:       lipgloss.NewStyle().Bold(true).Reverse(true),
	}
}
