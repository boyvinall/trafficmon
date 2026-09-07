package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// panelBorderWidth and panelBorderHeight are how much display space
// renderPanel adds on top of the content it wraps: 2 cells either side (1
// border + 1 padding), and 2 rows total (the inlaid-title top border plus
// the plain bottom border — there is no vertical padding, so those are the
// only two rows renderPanel itself spends).
//
// Anything sizing content to fit inside a panel — the header line, the
// table's columns — has to subtract panelBorderWidth from the panel's own
// outer width first; this is the one place that arithmetic is spelled out.
const (
	panelBorderWidth  = 4
	panelBorderHeight = 2
)

// panelBorderStyle is the box-drawing style every bordered panel uses, so
// panels added later share this one's look rather than picking their own.
var panelBorderStyle = lipgloss.RoundedBorder()

// renderPanel draws body inside a rounded, colored border sized to exactly
// outerWidth columns and outerHeight rows. If title is non-empty, it is
// inlaid in the top border (see renderPanelTitleBar) instead of taking up a
// line of the panel's own content.
func renderPanel(styles Styles, title string, outerWidth, outerHeight int, body string) string {
	// lipgloss's Width/Height already include padding in their budget — only
	// the border is subtracted here, not border+padding (that full
	// panelBorderWidth/Height is what a panel's content has to subtract,
	// since Padding(0, 1) is applied inside this same style).
	const borderWidth, borderHeight = 2, 2
	styleWidth := clamp(outerWidth-borderWidth, 1, outerWidth)
	styleHeight := clamp(outerHeight-borderHeight, 1, outerHeight)

	box := lipgloss.NewStyle().
		Border(panelBorderStyle, false, true, true, true). // no top: the title bar replaces it
		BorderForeground(colorBorder).
		Padding(0, 1).
		Width(styleWidth).
		Height(styleHeight).
		Render(body)

	return renderPanelTitleBar(styles, title, outerWidth) + "\n" + box
}

// renderPanelTitleBar draws a top border line of exactly outerWidth columns,
// inlaying title (if any) after the left corner, e.g. "╭─ Title ────╮".
func renderPanelTitleBar(styles Styles, title string, outerWidth int) string {
	corner, dash, endCorner := panelBorderStyle.TopLeft, panelBorderStyle.Top, panelBorderStyle.TopRight
	border := lipgloss.NewStyle().Foreground(colorBorder)

	if title == "" {
		return border.Render(corner + strings.Repeat(dash, max(outerWidth-2, 0)) + endCorner)
	}

	label := " " + title + " "
	remaining := max(outerWidth-2-1-lipgloss.Width(label), 0) // corners(2) + leading dash(1) + label

	var b strings.Builder
	b.WriteString(border.Render(corner + dash))
	b.WriteString(styles.PanelTitle.Render(label))
	b.WriteString(border.Render(strings.Repeat(dash, remaining) + endCorner))
	return b.String()
}
