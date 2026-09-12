package tui

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// pad lays s into a cell of exactly w display cells, against the requested
// side, truncating first if it does not fit. truncLeft selects truncateLeft
// over truncate for that first step — see column.truncLeft.
func pad(s string, w int, a alignment, truncLeft bool) string {
	if truncLeft {
		s = truncateLeft(s, w)
	} else {
		s = truncate(s, w)
	}

	gap := w - lipgloss.Width(s)
	if gap <= 0 {
		return s
	}
	if a == alignRight {
		return strings.Repeat(" ", gap) + s
	}
	return s + strings.Repeat(" ", gap)
}

// truncate shortens s to at most w display cells, marking the cut with an
// ellipsis.
//
// Over-long labels are truncated rather than wrapped because a wrapped cell
// would push every following row down by a line and break the alignment of the
// columns to its right.
func truncate(s string, w int) string {
	return truncateSide(s, w, false)
}

// truncateLeft shortens s to at most w display cells by dropping runes from
// the front rather than the back, marking the cut with a leading ellipsis.
//
// It exists for the breadcrumb, where the end of the string is the part worth
// keeping: the innermost scope is the one the rows on screen are actually
// filtered by, and the levels above it are context the user can recover by
// pressing esc.
func truncateLeft(s string, w int) string {
	return truncateSide(s, w, true)
}

// truncateSide is the rune-width-budget algorithm shared by truncate and
// truncateLeft: keep runes from one end of s up to a budget of w-1 display
// cells, and mark the runes dropped off the other end with an ellipsis.
//
// left runs the walk from the back of s instead of the front — reversing the
// runes first, keeping from the (now leading) end, then reversing the kept
// runes back is the same thing as walking from the end directly, so
// truncateLeft needs no separate loop of its own.
func truncateSide(s string, w int, left bool) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	if w == 1 {
		return "…"
	}

	// Measure rune by rune rather than slicing bytes: process names and IPv6
	// addresses are usually ASCII, but nothing guarantees it.
	runes := []rune(s)
	if left {
		reverseRunes(runes)
	}

	kept := make([]rune, 0, len(runes))
	used := 0
	for _, r := range runes {
		rw := lipgloss.Width(string(r))
		if used+rw > w-1 {
			break
		}
		kept = append(kept, r)
		used += rw
	}

	if left {
		reverseRunes(kept)
		return "…" + string(kept)
	}
	return string(kept) + "…"
}

// reverseRunes reverses runes in place.
func reverseRunes(runes []rune) {
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
}

// humanBytes formats a byte count for display, e.g. "128.0 MB".
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// humanRate formats a throughput for display, e.g. "2.1 MB/s".
func humanRate(bps float64) string {
	if math.IsNaN(bps) || bps < 0 {
		bps = 0
	}
	return humanBytes(uint64(bps)) + "/s"
}

// humanDuration formats a connection's age for display, netstat-style: plain
// seconds under a minute ("45s"), plain minutes under an hour ("12m"),
// hours+minutes under a day ("3h45m"), and days+hours beyond that
// ("12d05h"). Widest output is "999d23h" (7 cells) — sized for a realistic
// connection lifetime, the same way humanBytes/humanRate size their columns
// for a realistic byte count/rate rather than the full range a uint64 or
// float64 could hold.
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d/time.Hour), int(d/time.Minute)%60)
	default:
		return fmt.Sprintf("%dd%02dh", int(d/(24*time.Hour)), int(d/time.Hour)%24)
	}
}
