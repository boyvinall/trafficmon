package trafficmonreceiver

import (
	"testing"
	"time"
)

func TestSYNAttemptCacheRecordCountsWithinWindow(t *testing.T) {
	c := newSYNAttemptCache()
	key := synAttemptKey{localAddr: "10.0.0.5", localPort: 51000, remoteAddr: "93.184.216.34", remotePort: 443}
	base := time.Now()

	if got := c.record(key, base); got != 1 {
		t.Errorf("1st record = %d, want 1", got)
	}
	if got := c.record(key, base.Add(time.Minute)); got != 2 {
		t.Errorf("2nd record within window = %d, want 2", got)
	}
	// Far enough past the 2nd attempt (base+1m) that both it and the 1st
	// (base+0) have aged out of the window.
	if got := c.record(key, base.Add(time.Minute+synAttemptWindow+time.Second)); got != 1 {
		t.Errorf("record past window = %d, want 1 (all earlier attempts aged out)", got)
	}
}

func TestSYNAttemptCacheKeysAreIndependent(t *testing.T) {
	c := newSYNAttemptCache()
	a := synAttemptKey{localAddr: "10.0.0.5", localPort: 51000, remoteAddr: "93.184.216.34", remotePort: 443}
	b := synAttemptKey{localAddr: "10.0.0.5", localPort: 51000, remoteAddr: "93.184.216.34", remotePort: 8443}
	now := time.Now()

	c.record(a, now)
	c.record(a, now)
	if got := c.record(b, now); got != 1 {
		t.Errorf("distinct 4-tuple's count = %d, want 1", got)
	}
}

func TestSYNAttemptCachePruneDropsStaleKeys(t *testing.T) {
	c := newSYNAttemptCache()
	key := synAttemptKey{localAddr: "10.0.0.5", localPort: 51000, remoteAddr: "93.184.216.34", remotePort: 443}
	now := time.Now()

	c.record(key, now)
	c.prune(now.Add(synAttemptWindow + time.Second))

	if _, ok := c.attempts[key]; ok {
		t.Error("prune should have dropped a key with no attempts left in the window")
	}
}
