package aggregate

import (
	"net"
	"strconv"
)

// Grouping controls how finely the by-destination view buckets remote hosts.
type Grouping uint8

// Destination grouping modes, toggled with the `g` key.
const (
	// GroupByIP buckets every port of a remote host into one row.
	GroupByIP Grouping = iota
	// GroupByIPPort gives each remote IP:port its own row.
	GroupByIPPort
)

// ByDestination rolls connection records up by remote host, at the requested
// granularity.
//
// The row key doubles as the label because the address is what identifies the
// destination; net.JoinHostPort is used for the IP:port form so that an IPv6
// address comes out bracketed and stays parseable.
func ByDestination(snap Snapshot, g Grouping) []Row {
	key := func(c ConnectionRecord) string {
		if g == GroupByIPPort {
			return net.JoinHostPort(c.RemoteAddr, strconv.Itoa(int(c.RemotePort)))
		}
		return c.RemoteAddr
	}
	return rollup(snap.Connections, key, func(c ConnectionRecord, k string) Row {
		row := Row{Key: k, Label: k, RemoteAddr: c.RemoteAddr}
		if g == GroupByIPPort {
			row.RemotePort = c.RemotePort
		}
		return row
	})
}

// FilterByProcess narrows a snapshot to one process's connections, for the
// process-to-destination drill-down.
func FilterByProcess(snap Snapshot, pid int32) Snapshot {
	return filter(snap, func(c ConnectionRecord) bool { return c.PID == pid })
}
