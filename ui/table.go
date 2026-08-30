package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/boyvinall/mac-nethogs/aggregate"
)

// SortKey is the column driving row order, cycled with `s`.
type SortKey uint8

// Sort keys, in cycle order.
const (
	SortRate SortKey = iota
	SortTotal
	SortConnections
)

// sortRows orders rows by the active sort key, descending.
func sortRows(rows []aggregate.Row, k SortKey) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch k {
		case SortTotal:
			return a.BytesInTotal+a.BytesOutTotal > b.BytesInTotal+b.BytesOutTotal
		case SortConnections:
			return a.Connections > b.Connections
		default: // SortRate
			return a.RateInBps+a.RateOutBps > b.RateInBps+b.RateOutBps
		}
	})
}

// filterRows keeps only the rows whose label contains q, case-insensitively.
// An empty query keeps everything.
func filterRows(rows []aggregate.Row, q string) []aggregate.Row {
	if q == "" {
		return rows
	}

	q = strings.ToLower(q)
	out := rows[:0]
	for _, r := range rows {
		if strings.Contains(strings.ToLower(r.Label), q) {
			out = append(out, r)
		}
	}
	return out
}

// renderRows turns aggregated rows into table lines. Rate and cumulative total
// are always shown side by side; the sort key only decides the order.
//
// TODO(milestone 4): replace this with bubbles/table so columns align across
// rows instead of relying on fixed widths.
func renderRows(rows []aggregate.Row) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%-28s  ↓ %10s (%9s)  ↑ %10s (%9s)  %3d",
			r.Label,
			humanRate(r.RateInBps), humanBytes(r.BytesInTotal),
			humanRate(r.RateOutBps), humanBytes(r.BytesOutTotal),
			r.Connections))
	}
	return out
}

// humanBytes formats a byte count for display, e.g. "128 MB".
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
	return humanBytes(uint64(bps)) + "/s"
}
