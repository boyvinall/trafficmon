package aggregate

import "strconv"

// ByProcess rolls connection records up by owning PID.
//
// The PID is the row key rather than the process name: two processes can share
// a name, and a name can change under a PID, whereas the PID is what the
// drill-down filters on.
func ByProcess(snap Snapshot) []Row {
	return rollup(snap.Connections,
		func(c ConnectionRecord) string { return strconv.Itoa(int(c.PID)) },
		func(c ConnectionRecord, key string) Row {
			return Row{Key: key, Label: c.ProcessName, PID: c.PID}
		},
	)
}

// FilterByDestination narrows a snapshot to the connections talking to one
// remote host, for the destination-to-process drill-down. remotePort is only
// checked when g is GroupByIPPort, matching the granularity the drilled-into
// row was grouped at.
func FilterByDestination(snap Snapshot, remoteAddr string, remotePort uint16, g Grouping) Snapshot {
	return filter(snap, func(c ConnectionRecord) bool {
		if c.RemoteAddr != remoteAddr {
			return false
		}
		return g != GroupByIPPort || c.RemotePort == remotePort
	})
}
