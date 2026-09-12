package tui

import (
	"net"
	"strings"

	"github.com/boyvinall/trafficmon/aggregate"
)

// filterRows keeps only the rows matching q, case-insensitively. An empty
// query keeps everything.
//
// A row matches on its label or on the hostname annotating it, so that a
// destination can be found by the name the user knows it as — "github" finding
// 140.82.112.3 — as well as by the address on screen. Both are matched because
// only one of them is ever visible at a time on a narrow terminal, where the
// hostname column is the first to be dropped: filtering on the label alone
// would quietly stop finding hosts by name at exactly the width where the
// names disappeared. hostname may be nil in views that have no destinations.
//
// The result is built into rows[:0], reusing rows' backing array in place, so
// any other reference to rows is aliased and may be overwritten by this call.
func filterRows(rows []aggregate.Row, q string, hostname func(aggregate.Row) string) []aggregate.Row {
	if q == "" {
		return rows
	}

	q = strings.ToLower(q)
	out := rows[:0]
	for _, r := range rows {
		if strings.Contains(strings.ToLower(r.Label), q) {
			out = append(out, r)
			continue
		}
		if hostname != nil && strings.Contains(strings.ToLower(hostname(r)), q) {
			out = append(out, r)
		}
	}
	return out
}

// listenState is the TCP kernel state name every platform's procinfo backend
// reports for a socket accepting connections rather than carrying one — see
// procinfo's per-OS tcpStateName implementations.
const listenState = "LISTEN"

// filterListening keeps every row when show is true; otherwise it drops rows
// whose connection is in the LISTEN state — a socket that only ever accepts
// connections carries no traffic of its own to watch.
//
// Only the ungrouped view ever sets Row.State (see aggregate.Row's grouped
// constructors), so a grouped view is unaffected either way: there is nothing
// for this to drop until `g` cycles back to ungrouped.
//
// The result is built into rows[:0], reusing rows' backing array in place,
// the same trade filterRows makes and for the same reason.
func filterListening(rows []aggregate.Row, show bool) []aggregate.Row {
	if show {
		return rows
	}

	out := rows[:0]
	for _, r := range rows {
		if r.State != listenState {
			out = append(out, r)
		}
	}
	return out
}

// filterProto keeps rows whose transport protocol is currently shown,
// dropping tcp rows when showTCP is false and udp rows when showUDP is
// false. A row of any other protocol (icmp, arp, or "" on a grouped view
// that never sets Row.Proto — see aggregate.Row's grouped constructors) is
// unaffected by either flag: neither toggle claims to speak for it.
func filterProto(rows []aggregate.Row, showTCP, showUDP bool) []aggregate.Row {
	if showTCP && showUDP {
		return rows
	}

	out := rows[:0]
	for _, r := range rows {
		switch r.Proto {
		case "tcp":
			if !showTCP {
				continue
			}
		case "udp":
			if !showUDP {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// filterIPFamily keeps rows whose remote address family is currently shown,
// dropping IPv4 rows when showIPv4 is false and IPv6 rows when showIPv6 is
// false. A row whose remote address does not parse is never hidden, the
// same "unclassified rows are never hidden" rule filterProto/filterIface
// apply.
func filterIPFamily(rows []aggregate.Row, showIPv4, showIPv6 bool) []aggregate.Row {
	if showIPv4 && showIPv6 {
		return rows
	}

	out := rows[:0]
	for _, r := range rows {
		ip := net.ParseIP(r.RemoteAddr)
		switch {
		case ip == nil:
			out = append(out, r)
		case ip.To4() != nil:
			if showIPv4 {
				out = append(out, r)
			}
		default:
			if showIPv6 {
				out = append(out, r)
			}
		}
	}
	return out
}

// filterPrivate keeps every row when show is true; otherwise it drops rows
// whose remote address is RFC1918/RFC4193 private, via net.IP.IsPrivate. A
// row whose remote address does not parse is never hidden, the same
// convention filterIPFamily/filterProto/filterIface apply.
func filterPrivate(rows []aggregate.Row, show bool) []aggregate.Row {
	if show {
		return rows
	}

	out := rows[:0]
	for _, r := range rows {
		if ip := net.ParseIP(r.RemoteAddr); ip == nil || !ip.IsPrivate() {
			out = append(out, r)
		}
	}
	return out
}

// filterIface keeps rows whose capture interface is currently active in
// active. A row with no interface yet (Iface == "", no traffic seen for this
// connection) is never hidden, the same "unclassified rows are never
// hidden" rule filterProto applies to icmp/arp/grouped rows.
func filterIface(rows []aggregate.Row, active map[string]bool) []aggregate.Row {
	out := rows[:0]
	for _, r := range rows {
		if r.Iface == "" || active[r.Iface] {
			out = append(out, r)
		}
	}
	return out
}
