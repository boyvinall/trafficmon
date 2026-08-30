package aggregate

import "strconv"

// ByProcess rolls connection records up by owning PID.
//
// The PID is the row key rather than the process name: two processes can share
// a name, and a name can change under a PID, whereas the PID is what the
// drill-down filters on.
func ByProcess(snap Snapshot) []Row {
	return rollup(snap.Connections, func(c ConnectionRecord) (string, Row) {
		key := strconv.Itoa(int(c.PID))
		return key, Row{
			Key:   key,
			Label: c.ProcessName,
			PID:   c.PID,
		}
	})
}

// FilterByDestination narrows a snapshot to the connections talking to one
// remote host, for the destination-to-process drill-down.
func FilterByDestination(snap Snapshot, remoteAddr string, remotePort uint16, withPort bool) Snapshot {
	out := snap
	out.Connections = nil
	for _, c := range snap.Connections {
		if c.RemoteAddr != remoteAddr {
			continue
		}
		if withPort && c.RemotePort != remotePort {
			continue
		}
		out.Connections = append(out.Connections, c)
	}
	return out
}
