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
}

// DefaultStyles returns the standard theme.
func DefaultStyles() Styles {
	return Styles{
		Header:     lipgloss.NewStyle().Bold(true).Padding(0, 1),
		Breadcrumb: lipgloss.NewStyle().Faint(true),
		Footer:     lipgloss.NewStyle().Faint(true).Padding(0, 1),
		Selected:   lipgloss.NewStyle().Reverse(true),
		Closed:     lipgloss.NewStyle().Faint(true),
	}
}
