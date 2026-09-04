package aggregate

import "strconv"

// Grouping controls how connections roll up into rows, cycled with the `g`
// key.
type Grouping uint8

// Grouping modes, in cycle order.
const (
	// GroupNone shows one row per open connection.
	GroupNone Grouping = iota
	// GroupByPID rolls every connection owned by one process instance to
	// the same remote endpoint up into a single row.
	GroupByPID
	// GroupByProcessName rolls every connection sharing a process name and
	// talking to the same remote endpoint up into a single row, across
	// every PID currently running as that name.
	GroupByProcessName

	// numGroupings bounds the `g` cycle, so a new grouping only has to be
	// added above. It must stay last.
	numGroupings
)

// Next returns the grouping `g` cycles to, wrapping back round to GroupNone.
func (g Grouping) Next() Grouping { return (g + 1) % numGroupings }

// String names the grouping for the header bar.
func (g Grouping) String() string {
	switch g {
	case GroupByPID:
		return "By PID"
	case GroupByProcessName:
		return "By Process"
	default:
		return "Ungrouped"
	}
}

// Rows builds the table rows for snap at the requested grouping.
func Rows(snap Snapshot, g Grouping) []Row {
	switch g {
	case GroupByPID:
		return rowsByPID(snap)
	case GroupByProcessName:
		return rowsByProcessName(snap)
	default:
		return rowsUngrouped(snap)
	}
}

// rowsUngrouped returns one row per open connection.
//
// It still goes through rollup rather than a plain map so that a duplicate
// key — which should never occur, since a connKey is unique per open
// socket — accumulates rather than silently overwriting, the same safety
// rollup gives every other grouping.
func rowsUngrouped(snap Snapshot) []Row {
	return rollup(snap.Connections, connectionKey, func(c ConnectionRecord, key string) Row {
		return Row{
			Key:        key,
			Label:      c.ProcessName,
			PID:        c.PID,
			LocalAddr:  c.LocalAddr,
			LocalPort:  c.LocalPort,
			RemoteAddr: c.RemoteAddr,
			RemotePort: c.RemotePort,
			Proto:      c.Proto,
			State:      c.State,
			Hostname:   c.Hostname,
			Vanished:   c.Vanished,
		}
	})
}

// connectionKey identifies one connection record for rowsUngrouped's row
// key. It is the same tuple a socket is uniquely identified by, so two
// distinct connections never collide onto one row.
func connectionKey(c ConnectionRecord) string {
	return strconv.Itoa(int(c.PID)) + "|" + c.LocalAddr + "|" + strconv.Itoa(int(c.LocalPort)) +
		"|" + c.RemoteAddr + "|" + strconv.Itoa(int(c.RemotePort)) + "|" + c.Proto
}

// rowsByPID rolls connections up by owning PID and remote address:port, so a
// process talking to several destinations gets one row per destination
// rather than one row for the whole process.
//
// LocalAddr is seeded from whichever connection rollup happens to encounter
// first for that PID and destination: a process bound to several local
// addresses for the same remote endpoint only shows one representative, the
// same trade rollup already makes for every other per-row field a grouping
// can't give one answer for.
func rowsByPID(snap Snapshot) []Row {
	return rollup(snap.Connections,
		func(c ConnectionRecord) string { return pidRemoteKey(c) },
		func(c ConnectionRecord, key string) Row {
			return Row{
				Key:        key,
				Label:      c.ProcessName,
				PID:        c.PID,
				LocalAddr:  c.LocalAddr,
				RemoteAddr: c.RemoteAddr,
				RemotePort: c.RemotePort,
				Hostname:   c.Hostname,
			}
		},
	)
}

// rowsByProcessName rolls connections up by process name and remote
// address:port, across every PID currently running as that name.
func rowsByProcessName(snap Snapshot) []Row {
	return rollup(snap.Connections,
		func(c ConnectionRecord) string { return processRemoteKey(c) },
		func(c ConnectionRecord, key string) Row {
			return Row{Key: key, Label: c.ProcessName, RemoteAddr: c.RemoteAddr, RemotePort: c.RemotePort, Hostname: c.Hostname}
		},
	)
}

// pidRemoteKey identifies a rowsByPID group: one process instance talking to
// one remote endpoint.
func pidRemoteKey(c ConnectionRecord) string {
	return strconv.Itoa(int(c.PID)) + "|" + c.RemoteAddr + "|" + strconv.Itoa(int(c.RemotePort))
}

// processRemoteKey identifies a rowsByProcessName group: one process name
// talking to one remote endpoint, across every PID running as that name.
func processRemoteKey(c ConnectionRecord) string {
	return c.ProcessName + "|" + c.RemoteAddr + "|" + strconv.Itoa(int(c.RemotePort))
}
