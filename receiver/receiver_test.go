package trafficmonreceiver

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.uber.org/zap"

	"github.com/boyvinall/trafficmon/capture"
	"github.com/boyvinall/trafficmon/dpi"
)

// fakeLogFeedSource lets a test drive forwardLogs off channels it holds the
// send side of, standing in for a *capture.Capturer without a live pcap
// handle.
type fakeLogFeedSource struct {
	syn      chan capture.SYNEvent
	dnsQuery chan dpi.QueryFinding
	enabled  bool
}

func newFakeLogFeedSource(capacity int) *fakeLogFeedSource {
	return &fakeLogFeedSource{
		syn:      make(chan capture.SYNEvent, capacity),
		dnsQuery: make(chan dpi.QueryFinding, capacity),
		enabled:  true,
	}
}

func (f *fakeLogFeedSource) LogFeed() (<-chan capture.SYNEvent, <-chan dpi.QueryFinding, bool) {
	if !f.enabled {
		return nil, nil, false
	}
	return f.syn, f.dnsQuery, true
}

func (f *fakeLogFeedSource) LogFeedOverflow() (syn, dnsQuery uint64) {
	return 0, 0
}

func testReceiver() *trafficmonReceiver {
	return &trafficmonReceiver{cfg: NewDefaultConfig(), logger: zap.NewNop()}
}

// TestForwardLogsReturnsImmediatelyWhenDisabled asserts forwardLogs bails
// out as soon as the source reports its log feed isn't enabled, the same
// path Start takes when no logs consumer is configured — it never reaches
// the select loop or touches the consumer.
func TestForwardLogsReturnsImmediatelyWhenDisabled(t *testing.T) {
	r := testReceiver()
	source := &fakeLogFeedSource{enabled: false}
	sink := new(consumertest.LogsSink)

	done := make(chan struct{})
	go func() {
		r.forwardLogs(context.Background(), source, sink)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwardLogs did not return promptly when the log feed is disabled")
	}
	if sink.LogRecordCount() != 0 {
		t.Errorf("LogRecordCount() = %d, want 0", sink.LogRecordCount())
	}
}

// TestForwardLogsDeliversBurstBeyondOldRingCapacity sends more SYN events
// than the old drop-oldest ring's capacity (4096) in one burst, faster than
// logFlushInterval, and checks every one of them still reaches the
// consumer — the regression case a periodic ring-drain would have dropped
// once the ring filled up.
func TestForwardLogsDeliversBurstBeyondOldRingCapacity(t *testing.T) {
	const burst = 4096 + 500

	r := testReceiver()
	source := newFakeLogFeedSource(burst)
	sink := new(consumertest.LogsSink)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.forwardLogs(ctx, source, sink)
		close(done)
	}()

	base := time.Now()
	for i := range burst {
		source.syn <- capture.SYNEvent{LocalPort: uint16(i), At: base}
	}

	deadline := time.Now().Add(5 * time.Second)
	for sink.LogRecordCount() < burst && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done

	if got := sink.LogRecordCount(); got != burst {
		t.Fatalf("LogRecordCount() = %d, want %d (every SYN event delivered)", got, burst)
	}
}
