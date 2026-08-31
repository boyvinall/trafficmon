package capture

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestCapturerRecordAndSnapshot(t *testing.T) {
	c := New(DefaultConfig())
	now := time.Now().Truncate(time.Second)

	key := FlowKey{
		LocalAddr:  mustAddr(t, "192.168.1.10"),
		LocalPort:  51000,
		RemoteAddr: mustAddr(t, "140.82.112.3"),
		RemotePort: 443,
		Proto:      ProtoTCP,
	}

	// Two packets of each direction on one flow, plus one on another, to
	// prove the map keys them apart and the counters accumulate.
	c.record(key, now, 1000, false)
	c.record(key, now, 4000, true)
	c.record(key, now, 500, false)

	other := key
	other.RemotePort = 80
	c.record(other, now, 42, true)

	snap := c.Snapshot(now)
	if len(snap) != 2 {
		t.Fatalf("Snapshot() has %d flows, want 2", len(snap))
	}

	got := snap[key]
	if got.BytesOut != 1500 || got.BytesIn != 4000 {
		t.Errorf("totals = (in %d, out %d), want (4000, 1500)", got.BytesIn, got.BytesOut)
	}
	if want := 4000.0 / rateWindow.Seconds(); got.RateInBps != want {
		t.Errorf("RateInBps = %.1f, want %.1f", got.RateInBps, want)
	}
	if !got.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %s, want %s", got.LastSeen, now)
	}
}

func TestCapturerRecordReusesCounterPerFlow(t *testing.T) {
	c := New(DefaultConfig())
	now := time.Now()

	key := FlowKey{LocalAddr: mustAddr(t, "10.0.0.1"), LocalPort: 1, Proto: ProtoUDP}
	c.record(key, now, 1, true)
	first := c.flows[key]
	c.record(key, now, 1, true)

	if c.flows[key] != first {
		t.Fatal("record() replaced the counter for an existing flow")
	}
	if len(c.flows) != 1 {
		t.Fatalf("flow map has %d entries, want 1", len(c.flows))
	}
}

func TestListInterfaces(t *testing.T) {
	names, err := ListInterfaces()
	if err != nil {
		// libpcap enumeration needs elevated privileges on some hosts; nothing
		// to assert against there.
		t.Skipf("ListInterfaces() error = %v", err)
	}
	if names == nil {
		t.Fatal("ListInterfaces() = nil slice, want a non-nil slice")
	}
}

func TestDefaultInterfaceNamesARealDevice(t *testing.T) {
	name, err := DefaultInterface()
	if err != nil {
		// No default route and no capturable device: nothing to assert on a
		// machine that is offline or denies libpcap to a non-root test.
		t.Skipf("no default interface available: %v", err)
	}
	if _, err := net.InterfaceByName(name); err != nil {
		t.Fatalf("DefaultInterface() = %q, which the OS does not know: %v", name, err)
	}
}

// TestCapturerRunStopsOnContextCancel needs a live handle, so it only runs as
// root and outside -short.
func TestCapturerRunStopsOnContextCancel(t *testing.T) {
	if testing.Short() {
		t.Skip("opens a live pcap handle")
	}
	if os.Geteuid() != 0 {
		t.Skip("opening a pcap handle needs root")
	}

	iface, err := DefaultInterface()
	if err != nil {
		t.Skipf("no default interface: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Interface = iface

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- New(cfg).Run(ctx) }()

	// Give the handle time to open before pulling the rug out, so the test
	// exercises the read loop rather than the setup path.
	time.AfterFunc(200*time.Millisecond, cancel)

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return within 5s of cancellation")
	}
}

func TestCapturerEvictDropsStaleFlows(t *testing.T) {
	c := New(DefaultConfig())
	now := time.Now()

	fresh := FlowKey{LocalAddr: mustAddr(t, "10.0.0.1"), LocalPort: 1, Proto: ProtoTCP}
	stale := FlowKey{LocalAddr: mustAddr(t, "10.0.0.1"), LocalPort: 2, Proto: ProtoTCP}

	c.record(fresh, now, 100, true)
	c.record(stale, now.Add(-time.Minute), 100, true)

	if n := c.Evict(now.Add(-30 * time.Second)); n != 1 {
		t.Fatalf("Evict() removed %d flows, want 1", n)
	}
	if _, ok := c.flows[stale]; ok {
		t.Error("stale flow survived Evict()")
	}
	if _, ok := c.flows[fresh]; !ok {
		t.Error("Evict() removed a flow that was still active")
	}

	// A second pass with the same cutoff has nothing left to do.
	if n := c.Evict(now.Add(-30 * time.Second)); n != 0 {
		t.Errorf("second Evict() removed %d flows, want 0", n)
	}
}

func TestCapturerEvictConcurrentWithRecord(t *testing.T) {
	// Evict walks the map while holding the write lock and calls into each
	// counter's own lock; recording concurrently must not deadlock or race.
	c := New(DefaultConfig())
	now := time.Now()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := range 200 {
			key := FlowKey{LocalAddr: mustAddr(t, "10.0.0.1"), LocalPort: uint16(i % 16), Proto: ProtoUDP}
			c.record(key, now, 1, true)
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			c.Evict(now.Add(time.Second))
		}
	}()

	wg.Wait()
}
