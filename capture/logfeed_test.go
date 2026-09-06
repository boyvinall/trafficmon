package capture

import (
	"testing"

	"github.com/boyvinall/trafficmon/dpi"
)

func TestLogFeedSendSYNNonBlockingPastCapacity(t *testing.T) {
	f := newLogFeed()

	for range logFeedCapacity {
		f.sendSYN(SYNEvent{})
	}
	if syn, _ := f.overflow(); syn != 0 {
		t.Fatalf("overflow() syn = %d, want 0 before the channel is full", syn)
	}

	f.sendSYN(SYNEvent{})
	if syn, _ := f.overflow(); syn != 1 {
		t.Fatalf("overflow() syn = %d, want 1 after one send past capacity", syn)
	}

	f.sendSYN(SYNEvent{})
	if syn, _ := f.overflow(); syn != 2 {
		t.Fatalf("overflow() syn = %d, want 2 after two sends past capacity", syn)
	}
}

func TestLogFeedSendDNSQueryNonBlockingPastCapacity(t *testing.T) {
	f := newLogFeed()

	for range logFeedCapacity {
		f.sendDNSQuery(dpi.QueryFinding{})
	}
	if _, dnsQuery := f.overflow(); dnsQuery != 0 {
		t.Fatalf("overflow() dnsQuery = %d, want 0 before the channel is full", dnsQuery)
	}

	f.sendDNSQuery(dpi.QueryFinding{})
	if _, dnsQuery := f.overflow(); dnsQuery != 1 {
		t.Fatalf("overflow() dnsQuery = %d, want 1 after one send past capacity", dnsQuery)
	}
}

func TestCapturerLogFeedDisabledByDefault(t *testing.T) {
	c := New(DefaultConfig())

	syn, dnsQuery, ok := c.LogFeed()
	if ok {
		t.Fatal("LogFeed() ok = true, want false when EnableLogFeed is unset")
	}
	if syn != nil || dnsQuery != nil {
		t.Error("LogFeed() channels should be nil when disabled")
	}

	if syn, dnsQuery := c.LogFeedOverflow(); syn != 0 || dnsQuery != 0 {
		t.Errorf("LogFeedOverflow() = (%d, %d), want (0, 0) when disabled", syn, dnsQuery)
	}
}

func TestCapturerLogFeedEnabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableLogFeed = true
	c := New(cfg)

	syn, dnsQuery, ok := c.LogFeed()
	if !ok {
		t.Fatal("LogFeed() ok = false, want true when EnableLogFeed is set")
	}
	if syn == nil || dnsQuery == nil {
		t.Fatal("LogFeed() channels should be non-nil when enabled")
	}

	c.logFeed.sendSYN(SYNEvent{LocalPort: 1234})
	select {
	case ev := <-syn:
		if ev.LocalPort != 1234 {
			t.Errorf("received SYNEvent.LocalPort = %d, want 1234", ev.LocalPort)
		}
	default:
		t.Fatal("expected a SYNEvent on the syn channel")
	}
}
