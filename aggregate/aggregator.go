// Package aggregate joins the kernel's open-socket list with packet counters
// and rolls the result up into the rows the UI renders.
package aggregate

import (
	"sort"
	"sync"
	"time"

	"github.com/boyvinall/trafficmon/capture"
	"github.com/boyvinall/trafficmon/procinfo"
)

// GracePeriod bounds how long a connection lingers in the table, dimmed,
// after it stops appearing in the poller's socket enumeration.
//
// A poll only sees what is open at the instant it runs, once a second (see
// procinfo.PollInterval). Unlike TCP, which dwells in TIME_WAIT/CLOSE_WAIT
// for a while before the kernel actually drops the socket, a UDP socket can
// be opened and closed between two polls with nothing to catch it — so
// without this, a connection observed in one poll and gone by the next would
// vanish from the table instantly rather than staying visible long enough to
// notice. It also bounds how long capture's own flow counters are kept
// around (see Aggregator.Refresh), so a vanished-but-grace-held connection's
// bytes are not evicted out from under it early.
const GracePeriod = 5 * time.Second

// IdleThreshold is how long a connection with no state concept (UDP) must go
// without traffic before it counts as closed and renders dimmed.
//
// It is deliberately longer than one refresh tick. Packet timestamps come
// from the kernel at capture time while `now` comes from the UI's clock, so
// traffic that is still trickling along can easily read as a fraction of a
// second stale; dimming on the first such tick would make busy rows flicker
// in and out of the closed style.
const IdleThreshold = 2 * time.Second

// unattributedProcessLabel tags a row built from a capture flow that no
// socket can ever be enumerated for — ICMP and ARP have no kernel socket, so
// procinfo never reports a PID for them the way it does for every TCP/UDP
// row.
const unattributedProcessLabel = "(no process)"

// connKey identifies one open connection across refreshes, for the
// grace-period bookkeeping in Aggregator.join. It is not exported: nothing
// outside the join needs to name a connection this way.
type connKey struct {
	pid        int32
	localAddr  string
	localPort  uint16
	remoteAddr string
	remotePort uint16
	proto      string
}

// ConnectionRecord is one open connection: the socket procinfo currently
// reports — or, within GracePeriod of it vanishing, last reported — plus
// whatever traffic counters capture has for it.
type ConnectionRecord struct {
	// PID is the process that owns the socket, straight from procinfo: there
	// is no attribution to get wrong, since the connection only exists in
	// the first place because procinfo enumerated it on that PID.
	PID         int32
	ProcessName string

	LocalAddr  string
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	// Proto is the flow's transport protocol, e.g. "tcp" or "udp".
	Proto string
	// State is the TCP connection's kernel state (e.g. "ESTABLISHED",
	// "TIME_WAIT"), or "" for UDP and any other protocol with no state
	// concept.
	State string

	// BytesInTotal, BytesOutTotal, RateInBps and RateOutBps come from
	// joining against capture's flow counters, and stay zero until capture
	// has actually seen a packet for this connection.
	BytesInTotal  uint64
	BytesOutTotal uint64
	RateInBps     float64
	RateOutBps    float64

	// LastSeen is when the connection last carried traffic, or the zero
	// time if it never has.
	LastSeen time.Time

	// LastPolled is when procinfo's socket enumeration last actually
	// reported this connection. It drives Vanished and the grace-period
	// eviction in Aggregator.join, and is unrelated to LastSeen: a
	// connection can be freshly polled and have never carried a byte.
	LastPolled time.Time

	// Vanished is true once the connection is being shown only from the
	// aggregator's memory of an earlier poll, because the most recent poll
	// no longer reports it. It renders dimmed for the rest of its grace
	// period rather than disappearing the instant one poll misses it.
	Vanished bool
}

// Closed reports whether the connection has wound down and should render
// dimmed: it has vanished from the poller's enumeration, its TCP state shows
// it closing, or — for a protocol with no state concept — it has gone quiet
// after having carried traffic.
func (r ConnectionRecord) Closed(now time.Time) bool {
	if r.Vanished {
		return true
	}
	if r.State != "" {
		return closingTCPState(r.State)
	}
	return !r.LastSeen.IsZero() && now.Sub(r.LastSeen) > IdleThreshold
}

// closingTCPState reports whether state is one of the kernel's winding-down
// TCP states, as opposed to a connection that is listening or actively
// established.
func closingTCPState(state string) bool {
	switch state {
	case "CLOSE_WAIT", "LAST_ACK", "CLOSING", "TIME_WAIT", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSED":
		return true
	default:
		return false
	}
}

// less orders records deterministically. Records come out of a map, so
// without an explicit order the UI would see them shuffle on every frame.
func (r ConnectionRecord) less(o ConnectionRecord) bool {
	switch {
	case r.PID != o.PID:
		return r.PID < o.PID
	case r.RemoteAddr != o.RemoteAddr:
		return r.RemoteAddr < o.RemoteAddr
	case r.RemotePort != o.RemotePort:
		return r.RemotePort < o.RemotePort
	case r.LocalPort != o.LocalPort:
		return r.LocalPort < o.LocalPort
	default:
		return r.Proto < o.Proto
	}
}

// Row is one line in the table, at whatever grouping is active.
type Row struct {
	// Key identifies the row across refreshes so the UI can hold the cursor
	// on the same row as rows reorder. It is unique per connection when
	// ungrouped, and per PID or process name plus remote endpoint at the
	// coarser groupings.
	Key string

	// Label is the primary display string: the process name.
	Label string

	// PID is the owning process. It is meaningful when ungrouped or grouped
	// by PID; GroupByProcessName leaves it zero, since a process name can
	// cover more than one PID.
	PID int32

	// LocalAddr, LocalPort, RemoteAddr, RemotePort, Proto and State describe
	// one connection, and are only fully populated when ungrouped.
	// GroupByPID and GroupByProcessName both roll up per remote endpoint, so
	// RemoteAddr and RemotePort carry over exactly; GroupByPID additionally
	// keeps LocalAddr (a representative address — a multi-homed process only
	// shows one). LocalPort, Proto and State have no single answer once more
	// than one connection is rolled together, so every grouping drops them.
	LocalAddr  string
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	Proto      string
	State      string

	BytesInTotal  uint64
	BytesOutTotal uint64
	RateInBps     float64
	RateOutBps    float64

	Connections int
	LastSeen    time.Time
	// Vanished mirrors ConnectionRecord.Vanished. rollup leaves it at its
	// zero value for a grouped row: a summary of many connections in mixed
	// presence has no single answer, so grouped rows are never dimmed.
	Vanished bool
}

// Closed reports whether the row should render dimmed. See
// ConnectionRecord.Closed; the same rule applies at the row level.
func (r Row) Closed(now time.Time) bool {
	if r.Vanished {
		return true
	}
	if r.State != "" {
		return closingTCPState(r.State)
	}
	return !r.LastSeen.IsZero() && now.Sub(r.LastSeen) > IdleThreshold
}

// Snapshot is everything the UI needs for one frame.
type Snapshot struct {
	// At is when the snapshot was taken. No production code reads it back —
	// it exists for tests and fixtures that want a timestamped Snapshot to
	// build on.
	At          time.Time
	Connections []ConnectionRecord
}

// Aggregator owns the shared state written by the capture and poller
// goroutines and read by the UI.
type Aggregator struct {
	cap  *capture.Capturer
	poll *procinfo.Poller

	// mu guards records. It is a plain Mutex, not an RWMutex: join is the
	// only method that ever touches records, and it always writes, so there
	// is no read-only path to give a separate RLock.
	mu sync.Mutex
	// records is the previous join result, keyed by connection. Retaining it
	// across refreshes is what lets a connection missing from the latest
	// poll stay on screen, dimmed, for the rest of its GracePeriod.
	records map[connKey]ConnectionRecord
}

// New wires an Aggregator to its two data sources.
func New(c *capture.Capturer, p *procinfo.Poller) *Aggregator {
	return &Aggregator{
		cap:     c,
		poll:    p,
		records: make(map[connKey]ConnectionRecord),
	}
}

// Refresh performs the join: the poller's open-connection list x capture's
// flow counters, producing the connection records the views are built from.
func (a *Aggregator) Refresh(now time.Time) Snapshot {
	snap := a.join(a.poll.Connections(), a.cap.Snapshot(now), now)

	// Drop the counters behind whatever can no longer possibly be on
	// screen. The capture side never forgets a flow on its own, so without
	// this its table grows by one counter per connection ever seen for the
	// life of the process. The cutoff matches GracePeriod, the longest a
	// vanished connection can still be showing its last-known bytes.
	a.cap.Evict(now.Add(-GracePeriod))

	return snap
}

// join matches every open connection to whatever capture counters exist for
// it, carries forward anything the poll missed that is still within its
// grace period, and returns the resulting snapshot.
//
// It takes both inputs as arguments rather than reading them from the two
// sources so that the join — where all the interesting cases live — can be
// exercised with hand-built inputs, no live interface and no root.
func (a *Aggregator) join(conns []procinfo.Connection, flows map[capture.FlowKey]capture.FlowStats, now time.Time) Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()

	records := make(map[connKey]ConnectionRecord, len(conns))
	seen := make(map[connKey]bool, len(conns))

	for _, c := range conns {
		key := connKey{
			pid:        c.PID,
			localAddr:  c.LocalAddr.String(),
			localPort:  c.LocalPort,
			remoteAddr: c.RemoteAddr.String(),
			remotePort: c.RemotePort,
			proto:      c.Proto,
		}
		seen[key] = true

		rec := ConnectionRecord{
			PID:         c.PID,
			ProcessName: c.ProcessName,
			LocalAddr:   key.localAddr,
			LocalPort:   c.LocalPort,
			RemoteAddr:  key.remoteAddr,
			RemotePort:  c.RemotePort,
			Proto:       c.Proto,
			State:       c.State,
			LastPolled:  now,
		}

		flowKey := capture.FlowKey{
			LocalAddr:  c.LocalAddr,
			LocalPort:  c.LocalPort,
			RemoteAddr: c.RemoteAddr,
			RemotePort: c.RemotePort,
			Proto:      protoFromString(c.Proto),
		}
		if st, ok := flows[flowKey]; ok {
			rec.BytesInTotal, rec.BytesOutTotal = st.BytesIn, st.BytesOut
			rec.RateInBps, rec.RateOutBps = st.RateInBps, st.RateOutBps
			rec.LastSeen = st.LastSeen
		}

		records[key] = rec
	}

	// ICMP and ARP flows have no socket for procinfo to have enumerated, so
	// they never appear in conns above. They still deserve a row — just one
	// with no PID/process — so pick them out of the capture flows directly.
	// A key built here can never collide with one built from conns, since
	// procinfo.Connection.Proto is always "tcp" or "udp".
	for fk, st := range flows {
		if fk.Proto != capture.ProtoICMP && fk.Proto != capture.ProtoARP {
			continue
		}

		key := connKey{
			localAddr:  fk.LocalAddr.String(),
			localPort:  fk.LocalPort,
			remoteAddr: fk.RemoteAddr.String(),
			remotePort: fk.RemotePort,
			proto:      fk.Proto.String(),
		}
		seen[key] = true
		records[key] = ConnectionRecord{
			ProcessName:   unattributedProcessLabel,
			LocalAddr:     key.localAddr,
			LocalPort:     fk.LocalPort,
			RemoteAddr:    key.remoteAddr,
			RemotePort:    fk.RemotePort,
			Proto:         key.proto,
			LastPolled:    now,
			BytesInTotal:  st.BytesIn,
			BytesOutTotal: st.BytesOut,
			RateInBps:     st.RateInBps,
			RateOutBps:    st.RateOutBps,
			LastSeen:      st.LastSeen,
		}
	}

	// Carry forward anything the current poll missed, as long as it is
	// still within its grace period.
	cutoff := now.Add(-GracePeriod)
	for key, prev := range a.records {
		if seen[key] || prev.LastPolled.Before(cutoff) {
			continue
		}
		prev.Vanished = true
		records[key] = prev
	}

	// Replacing the map wholesale, rather than patching it, is what stops a
	// connection past its grace period lingering as a record forever.
	a.records = records

	list := make([]ConnectionRecord, 0, len(records))
	for _, r := range records {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].less(list[j]) })

	return Snapshot{At: now, Connections: list}
}

// protoFromString converts a procinfo/aggregate proto string ("tcp"/"udp")
// into the enum capture.FlowKey is keyed on. procinfo.SocketsForPID never
// reports anything else, so an unrecognised value falls back to TCP rather
// than needing a third, meaningless zero value of its own.
func protoFromString(s string) capture.Proto {
	if s == "udp" {
		return capture.ProtoUDP
	}
	return capture.ProtoTCP
}

// rollup groups records into rows and sums their counters. key maps a record
// to its row key; seed builds the row that key starts life as, and runs only
// on that key's first occurrence — everything after that is pure accumulation
// through the row already in rows.
//
// Rows come out in order of first appearance, and the join has already sorted
// the records, so the row order is stable from frame to frame even before the
// UI applies its own sort.
func rollup(records []ConnectionRecord, key func(ConnectionRecord) string, seed func(ConnectionRecord, string) Row) []Row {
	index := make(map[string]int, len(records))
	// rows is pre-sized to cap(records), and the number of distinct keys can
	// never exceed the number of records, so the append below never grows past
	// that capacity and never reallocates — which is what makes it safe to keep
	// holding &rows[i] and mutating through it across later iterations.
	rows := make([]Row, 0, len(records))

	for _, c := range records {
		k := key(c)
		i, ok := index[k]
		if !ok {
			i = len(rows)
			index[k] = i
			rows = append(rows, seed(c, k))
		}

		r := &rows[i]
		r.BytesInTotal += c.BytesInTotal
		r.BytesOutTotal += c.BytesOutTotal
		r.RateInBps += c.RateInBps
		r.RateOutBps += c.RateOutBps
		r.Connections++
		if c.LastSeen.After(r.LastSeen) {
			r.LastSeen = c.LastSeen
		}
	}

	return rows
}
