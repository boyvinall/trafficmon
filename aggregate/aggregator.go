// Package aggregate joins packet counters with process attribution and rolls
// the result up into the views the UI renders.
package aggregate

import (
	"sort"
	"sync"
	"time"

	"github.com/boyvinall/mac-nethogs/capture"
	"github.com/boyvinall/mac-nethogs/procinfo"
)

// GracePeriod is how long a row with no traffic stays visible (dimmed) before
// being evicted.
const GracePeriod = 5 * time.Second

// IdleThreshold is how long a connection must go without traffic before it
// counts as closed and renders dimmed.
//
// It is deliberately longer than one refresh tick. Packet timestamps come from
// the kernel at capture time while `now` comes from the UI's clock, so a flow
// that is still trickling along can easily read as a fraction of a second
// stale; dimming on the first such tick would make busy rows flicker in and
// out of the closed style.
const IdleThreshold = 2 * time.Second

// UnknownProcess is the bucket for traffic whose local port matched no polled
// socket — the process exited, or attribution lost a race. Traffic is never
// dropped on the floor.
var UnknownProcess = procinfo.Process{PID: -1, Name: "unknown"}

// ConnectionRecord is one joined flow: byte counters plus the process that
// owned the local port at join time.
type ConnectionRecord struct {
	PID         int32
	ProcessName string

	LocalAddr  string
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	Proto      string

	BytesInTotal  uint64
	BytesOutTotal uint64
	RateInBps     float64
	RateOutBps    float64

	LastSeen time.Time
}

// Closed reports whether the connection has gone quiet and should render
// dimmed. The aggregator evicts it once it has been quiet for GracePeriod.
func (r ConnectionRecord) Closed(now time.Time) bool {
	return now.Sub(r.LastSeen) > IdleThreshold
}

// less orders records deterministically. Records come out of a map, so without
// an explicit order the UI would see them shuffle on every frame.
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

// Row is one aggregated line in the table, in either top-level mode.
type Row struct {
	// Key identifies the row across refreshes so the UI can hold the cursor on
	// the same row as rows reorder. It is the PID in by-process mode and the
	// remote IP or IP:port in by-destination mode.
	Key string

	// Label is the primary display string: the process name, or the remote
	// address at the current grouping.
	Label string

	// PID is the owning process. It is only meaningful on rows produced by
	// ByProcess, which is also the only view that renders it as a column;
	// ByDestination leaves it zero.
	PID int32

	// RemoteAddr and RemotePort describe the destination. They are only set by
	// ByDestination, and RemotePort stays zero when grouping by IP alone. The
	// UI needs them split out to drill down into a destination without having
	// to parse Label back apart.
	RemoteAddr string
	RemotePort uint16

	BytesInTotal  uint64
	BytesOutTotal uint64
	RateInBps     float64
	RateOutBps    float64

	Connections int
	LastSeen    time.Time
}

// Closed reports whether every connection behind the row has gone quiet, so
// the UI can dim it. LastSeen is the newest of the row's connections, so a
// single live connection keeps the whole row lit.
func (r Row) Closed(now time.Time) bool {
	return now.Sub(r.LastSeen) > IdleThreshold
}

// Snapshot is everything the UI needs for one frame.
type Snapshot struct {
	At          time.Time
	Connections []ConnectionRecord
}

// Aggregator owns the shared state written by the capture and poller
// goroutines and read by the UI.
type Aggregator struct {
	cap  *capture.Capturer
	poll *procinfo.Poller

	mu sync.RWMutex
	// records is the previous join result, keyed by flow. Retaining it across
	// refreshes is what lets a connection whose owning process has already
	// exited keep its name for the rest of its grace period.
	records map[capture.FlowKey]ConnectionRecord
	last    Snapshot
}

// New wires an Aggregator to its two data sources.
func New(c *capture.Capturer, p *procinfo.Poller) *Aggregator {
	return &Aggregator{
		cap:     c,
		poll:    p,
		records: make(map[capture.FlowKey]ConnectionRecord),
	}
}

// Refresh performs the join: flow snapshot x port map, producing the
// connection records the views are built from.
func (a *Aggregator) Refresh(now time.Time) Snapshot {
	snap := a.join(a.cap.Snapshot(now), a.poll.Snapshot(), now)

	// Drop the counters behind the records that just aged out. The capture
	// side never forgets a flow on its own, so without this its table grows by
	// one counter per connection ever seen for the life of the process.
	a.cap.Evict(now.Add(-GracePeriod))

	return snap
}

// join matches every captured flow to the process that currently owns its
// local port, ages out whatever has been quiet for longer than GracePeriod,
// and publishes the result as the latest snapshot.
//
// It takes both maps as arguments rather than reading them from the two
// sources so that the join — where all the interesting cases live — can be
// exercised with hand-built inputs, no live interface and no root.
func (a *Aggregator) join(flows map[capture.FlowKey]capture.FlowStats, ports map[uint16]procinfo.Process, now time.Time) Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := now.Add(-GracePeriod)
	records := make(map[capture.FlowKey]ConnectionRecord, len(flows))

	for key, st := range flows {
		// Past the grace period the row is gone from the UI, so there is
		// nothing left to remember the flow for.
		if st.LastSeen.Before(cutoff) {
			continue
		}

		proc := a.attribute(key, ports)
		records[key] = ConnectionRecord{
			PID:           proc.PID,
			ProcessName:   proc.Name,
			LocalAddr:     key.LocalAddr.String(),
			LocalPort:     key.LocalPort,
			RemoteAddr:    key.RemoteAddr.String(),
			RemotePort:    key.RemotePort,
			Proto:         key.Proto.String(),
			BytesInTotal:  st.BytesIn,
			BytesOutTotal: st.BytesOut,
			RateInBps:     st.RateInBps,
			RateOutBps:    st.RateOutBps,
			LastSeen:      st.LastSeen,
		}
	}

	// Replacing the map wholesale, rather than patching it, is what stops an
	// expired or capture-evicted flow lingering as a record forever.
	a.records = records

	list := make([]ConnectionRecord, 0, len(records))
	for _, r := range records {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].less(list[j]) })

	snap := Snapshot{At: now, Connections: list}
	a.last = snap
	return snap
}

// attribute resolves the process owning a flow's local port. Caller must hold
// a.mu.
//
// The current poll always wins. A local port can be recycled onto a new
// process within a second or two, and merging the two processes' traffic would
// silently misreport both, so a PID remembered from an earlier refresh is
// never allowed to override a freshly polled one.
//
// The remembered PID is only a fallback, for a flow whose owner has already
// exited: that keeps a closing connection labelled with the process that
// actually made it for the few seconds it stays on screen, instead of having
// every row flip to "unknown" on its way out. A flow that was never attributed
// still lands in UnknownProcess.
func (a *Aggregator) attribute(key capture.FlowKey, ports map[uint16]procinfo.Process) procinfo.Process {
	if proc, ok := ports[key.LocalPort]; ok {
		return proc
	}
	if prev, ok := a.records[key]; ok && prev.PID != UnknownProcess.PID {
		return procinfo.Process{PID: prev.PID, Name: prev.ProcessName}
	}
	return UnknownProcess
}

// Latest returns the most recent snapshot without recomputing it — used when
// the UI is paused.
func (a *Aggregator) Latest() Snapshot {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.last
}

// rollup groups records into rows and sums their counters. seed maps a record
// to its row key and to the row that key starts life as; everything after that
// is pure accumulation.
//
// Rows come out in order of first appearance, and the join has already sorted
// the records, so the row order is stable from frame to frame even before the
// UI applies its own sort.
func rollup(records []ConnectionRecord, seed func(ConnectionRecord) (string, Row)) []Row {
	index := make(map[string]int, len(records))
	rows := make([]Row, 0, len(records))

	for _, c := range records {
		key, row := seed(c)
		i, ok := index[key]
		if !ok {
			i = len(rows)
			index[key] = i
			rows = append(rows, row)
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
