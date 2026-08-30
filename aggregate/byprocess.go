package aggregate

// ByProcess rolls connection records up by owning PID.
//
// TODO(milestone 3): sum counters per PID and count connections.
func ByProcess(snap Snapshot) []Row {
	_ = snap
	return nil
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
