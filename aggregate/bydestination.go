package aggregate

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
// TODO(milestone 3): sum counters per destination key and count connections.
func ByDestination(snap Snapshot, g Grouping) []Row {
	_ = snap
	_ = g
	return nil
}

// FilterByProcess narrows a snapshot to one process's connections, for the
// process-to-destination drill-down.
func FilterByProcess(snap Snapshot, pid int32) Snapshot {
	out := snap
	out.Connections = nil
	for _, c := range snap.Connections {
		if c.PID == pid {
			out.Connections = append(out.Connections, c)
		}
	}
	return out
}
