// Package aggregate joins packet counters with process attribution and rolls
// the result up into the views the UI renders.
package aggregate

import (
	"sync"
	"time"

	"github.com/boyvinall/mac-nethogs/capture"
	"github.com/boyvinall/mac-nethogs/procinfo"
)

// GracePeriod is how long a row with no traffic stays visible (dimmed) before
// being evicted.
const GracePeriod = 5 * time.Second

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
// dimmed. Callers evict once Age exceeds GracePeriod.
func (r ConnectionRecord) Closed(now time.Time) bool {
	return now.Sub(r.LastSeen) > time.Second
}

// Row is one aggregated line in the table, in either top-level mode.
type Row struct {
	// Key is the PID (by-process mode) or the remote IP / IP:port
	// (by-destination mode).
	Key   string
	Label string

	BytesInTotal  uint64
	BytesOutTotal uint64
	RateInBps     float64
	RateOutBps    float64

	Connections int
	LastSeen    time.Time
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

	mu   sync.RWMutex
	last Snapshot
}

// New wires an Aggregator to its two data sources.
func New(c *capture.Capturer, p *procinfo.Poller) *Aggregator {
	return &Aggregator{cap: c, poll: p}
}

// Refresh performs the join: flow snapshot x port map, producing the
// connection records the views are built from.
//
// TODO(milestone 3): join on local port, bucket misses into UnknownProcess,
// and retain quiet records until GracePeriod lapses.
func (a *Aggregator) Refresh(now time.Time) Snapshot {
	flows := a.cap.Snapshot(now)
	ports := a.poll.Snapshot()

	records := make([]ConnectionRecord, 0, len(flows))
	_ = ports

	snap := Snapshot{At: now, Connections: records}

	a.mu.Lock()
	a.last = snap
	a.mu.Unlock()

	return snap
}

// Latest returns the most recent snapshot without recomputing it — used when
// the UI is paused.
func (a *Aggregator) Latest() Snapshot {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.last
}
