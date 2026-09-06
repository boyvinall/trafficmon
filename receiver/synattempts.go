package trafficmonreceiver

import (
	"fmt"
	"time"

	"github.com/boyvinall/trafficmon/capture"
)

// synAttemptWindow is how far back synAttemptCache counts prior SYNs to the
// same 4-tuple when annotating a SYN log record's attempt count.
const synAttemptWindow = 3 * time.Minute

// synAttemptKey identifies one connection attempt's exact 4-tuple — both the
// local and remote address:port, not just the remote peer — so a count
// reflects repeated attempts from this specific local endpoint rather than
// merely to this remote one.
type synAttemptKey struct {
	localAddr, remoteAddr string
	localPort, remotePort uint16
}

// synAttemptCache tracks, per 4-tuple, the timestamps of SYNs seen within
// the trailing synAttemptWindow, entirely in memory and owned by the single
// collect goroutine that calls record/prune — no mutex needed.
type synAttemptCache struct {
	attempts map[synAttemptKey][]time.Time
}

func newSYNAttemptCache() *synAttemptCache {
	return &synAttemptCache{attempts: make(map[synAttemptKey][]time.Time)}
}

// record appends at to key's history and returns the resulting count of
// attempts still within synAttemptWindow of at, this one included.
func (c *synAttemptCache) record(key synAttemptKey, at time.Time) int {
	hist := c.attempts[key]
	hist = append(hist, at)
	hist = pruneBefore(hist, at.Add(-synAttemptWindow))
	c.attempts[key] = hist
	return len(hist)
}

// prune drops every 4-tuple whose most recent SYN has aged out of
// synAttemptWindow as of now, so a connection attempt pattern that has
// stopped doesn't linger in the cache forever.
func (c *synAttemptCache) prune(now time.Time) {
	cutoff := now.Add(-synAttemptWindow)
	for key, hist := range c.attempts {
		hist = pruneBefore(hist, cutoff)
		if len(hist) == 0 {
			delete(c.attempts, key)
			continue
		}
		c.attempts[key] = hist
	}
}

// pruneBefore removes every timestamp at or before cutoff from hist,
// in place.
func pruneBefore(hist []time.Time, cutoff time.Time) []time.Time {
	n := 0
	for _, t := range hist {
		if t.After(cutoff) {
			hist[n] = t
			n++
		}
	}
	return hist[:n]
}

// synAttemptKeyFor builds ev's cache key.
func synAttemptKeyFor(ev capture.SYNEvent) synAttemptKey {
	return synAttemptKey{
		localAddr:  ev.LocalAddr.String(),
		localPort:  ev.LocalPort,
		remoteAddr: ev.RemoteAddr.String(),
		remotePort: ev.RemotePort,
	}
}

// String renders k for log bodies, e.g. "10.0.0.5:51423 -> 93.184.216.34:443".
func (k synAttemptKey) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d", k.localAddr, k.localPort, k.remoteAddr, k.remotePort)
}
