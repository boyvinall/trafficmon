package tui

import (
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/lipgloss"
)

// colorBorder and colorTitle anchor the theme: every style below is expressed
// in terms of them (or the semantic OK/fail colors) rather than a bare ANSI
// number of its own, so retuning the palette only ever means editing this one
// block.
var (
	colorBorder = lipgloss.Color("12") // blue, the focused panel's border
	colorTitle  = lipgloss.Color("11") // yellow, the focused panel's title
	colorOK     = lipgloss.Color("2")  // green
	colorFail   = lipgloss.Color("1")  // red

	// colorBorderBlurred and colorTitleBlurred are the unfocused panel's
	// border and title colors — dim enough to read as clearly secondary to
	// colorBorder/colorTitle without vanishing on a dark terminal.
	colorBorderBlurred = lipgloss.Color("4") // dim blue
	colorTitleBlurred  = lipgloss.Color("8") // grey
)

// Styles holds every lipgloss style the UI uses, so themes live in one place.
type Styles struct {
	// Header marks out the title bar naming the app and the current view.
	Header lipgloss.Style
	// Breadcrumb renders the header's drill path and status segments, which
	// are secondary to the title they hang off.
	Breadcrumb lipgloss.Style
	// Live marks the header's "live" flag, the counterpart to Paused: a
	// capture that is actually running gets the same OK green a completed
	// sample gets elsewhere in the theme.
	Live lipgloss.Style
	// Footer marks out the key-hint line (or the filter input in its place)
	// from the table above it.
	Footer lipgloss.Style
	// Selected highlights the row under the cursor.
	Selected lipgloss.Style
	// Closed dims rows whose connections have all gone away but are still
	// inside the grace period.
	Closed lipgloss.Style
	// EventInfo colors the events panel's LVL cell for an info-severity row
	// (SYN, DNS Q, DNS A) — the only colored cell in an otherwise-plain row.
	EventInfo lipgloss.Style
	// EventError is EventInfo's counterpart for an error-severity row (RST,
	// DNS ERR).
	EventError lipgloss.Style
	// ColumnHeader marks out the table's title row from the data beneath it.
	ColumnHeader lipgloss.Style
	// PanelTitle renders a panel's name, inlaid into its top border.
	PanelTitle lipgloss.Style
	// PanelTitleBlurred renders the same, for whichever panel does not
	// currently have focus.
	PanelTitleBlurred lipgloss.Style
	// Paused flags frozen capture in the header bar. It is deliberately louder
	// than the rest of the bar: a paused table looks exactly like a live one
	// that has gone quiet, so the indicator is the only thing telling the two
	// apart.
	Paused lipgloss.Style
}

// DefaultStyles returns the standard theme.
func DefaultStyles() Styles {
	return Styles{
		Header:            lipgloss.NewStyle().Bold(true).Foreground(colorTitle).Padding(0, 1),
		Breadcrumb:        lipgloss.NewStyle().Faint(true),
		Live:              lipgloss.NewStyle().Foreground(colorOK),
		Footer:            lipgloss.NewStyle().Bold(true).Foreground(colorTitle).Padding(0, 1),
		Selected:          lipgloss.NewStyle().Reverse(true),
		Closed:            lipgloss.NewStyle().Faint(true),
		EventInfo:         lipgloss.NewStyle().Foreground(colorOK),
		EventError:        lipgloss.NewStyle().Foreground(colorFail),
		ColumnHeader:      lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Bold(true),
		PanelTitle:        lipgloss.NewStyle().Bold(true).Foreground(colorTitle),
		PanelTitleBlurred: lipgloss.NewStyle().Foreground(colorTitleBlurred),
		Paused:            lipgloss.NewStyle().Bold(true).Foreground(colorFail),
	}
}

// HelpStyles returns the key/description colors for the footer hint line and
// the `?` overlay. bubbles/help's own defaults are tuned for a dense
// single-line footer coexisting with a lot of other on-screen text — its
// description color on a dark terminal is close enough to black to be
// nearly unreadable in the far roomier `?` overlay — so this reuses the
// theme's own colors instead of the package default.
func HelpStyles() help.Styles {
	keyStyle := lipgloss.NewStyle().Bold(true).Foreground(colorTitle)
	descStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	sepStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	return help.Styles{
		ShortKey:       keyStyle,
		ShortDesc:      descStyle,
		ShortSeparator: sepStyle,
		Ellipsis:       sepStyle,
		FullKey:        keyStyle,
		FullDesc:       descStyle,
		FullSeparator:  sepStyle,
	}
}
