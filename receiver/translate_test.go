package trafficmonreceiver

import (
	"net/netip"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/boyvinall/trafficmon/aggregate"
	"github.com/boyvinall/trafficmon/capture"
	"github.com/boyvinall/trafficmon/dpi"
	"github.com/boyvinall/trafficmon/receiver/internal/metadata"
)

// findMetric returns the named metric from md's first (only) scope, or nil.
func findMetric(md pmetric.Metrics, name string) *pmetric.Metric {
	sms := md.ResourceMetrics().At(0).ScopeMetrics()
	ms := sms.At(0).Metrics()
	for i := 0; i < ms.Len(); i++ {
		m := ms.At(i)
		if m.Name() == name {
			return &m
		}
	}
	return nil
}

// findDataPoint returns the first data point in points whose attributes
// match every key/value in want.
func findDataPoint(points pmetric.NumberDataPointSlice, want map[string]any) (pmetric.NumberDataPoint, bool) {
	for i := 0; i < points.Len(); i++ {
		dp := points.At(i)
		match := true
		for k, v := range want {
			got, ok := dp.Attributes().Get(k)
			if !ok {
				match = false
				break
			}
			switch want := v.(type) {
			case string:
				if got.Str() != want {
					match = false
				}
			case int64:
				if got.Int() != want {
					match = false
				}
			case bool:
				if got.Bool() != want {
					match = false
				}
			}
			if !match {
				break
			}
		}
		if match {
			return dp, true
		}
	}
	return pmetric.NumberDataPoint{}, false
}

func TestBuildMetricsNetworkIO(t *testing.T) {
	now := time.Now()
	firstSeen := now.Add(-time.Minute)

	snap := aggregate.Snapshot{
		At: now,
		Connections: []aggregate.ConnectionRecord{
			{
				PID:           1234,
				ProcessName:   "curl",
				LocalAddr:     "10.0.0.5",
				LocalPort:     51000,
				RemoteAddr:    "93.184.216.34",
				RemotePort:    443,
				Proto:         "tcp",
				BytesInTotal:  2000,
				BytesOutTotal: 500,
				FirstSeen:     firstSeen,
				Iface:         "en0",
			},
		},
	}

	cfg := NewDefaultConfig()
	state := newMetricsState(now.Add(-time.Hour))
	md := state.buildMetrics(snap, now, cfg)

	m := findMetric(md, metadata.MetricNetworkIO)
	if m == nil {
		t.Fatal("trafficmon.network.io metric not found")
	}
	if m.Sum().AggregationTemporality() != pmetric.AggregationTemporalityCumulative {
		t.Errorf("expected cumulative temporality, got %v", m.Sum().AggregationTemporality())
	}
	if !m.Sum().IsMonotonic() {
		t.Error("expected monotonic sum")
	}

	rx, ok := findDataPoint(m.Sum().DataPoints(), map[string]any{
		metadata.AttrNetworkIODirection: metadata.AttrDirectionReceive,
		"network.peer.address":          "93.184.216.34",
		"network.peer.port":             int64(443),
		"process.pid":                   int64(1234),
	})
	if !ok {
		t.Fatal("receive data point not found")
	}
	if rx.IntValue() != 2000 {
		t.Errorf("receive bytes = %d, want 2000", rx.IntValue())
	}
	if !rx.StartTimestamp().AsTime().Equal(firstSeen) {
		t.Errorf("start timestamp = %v, want %v", rx.StartTimestamp().AsTime(), firstSeen)
	}

	tx, ok := findDataPoint(m.Sum().DataPoints(), map[string]any{
		metadata.AttrNetworkIODirection: metadata.AttrDirectionTransmit,
	})
	if !ok {
		t.Fatal("transmit data point not found")
	}
	if tx.IntValue() != 500 {
		t.Errorf("transmit bytes = %d, want 500", tx.IntValue())
	}
}

func TestBuildMetricsCardinalityOverflow(t *testing.T) {
	now := time.Now()
	cfg := NewDefaultConfig()
	cfg.MaxPeerCardinality = 1

	snap := aggregate.Snapshot{
		At: now,
		Connections: []aggregate.ConnectionRecord{
			{PID: 1, RemoteAddr: "1.1.1.1", RemotePort: 80, Proto: "tcp", BytesInTotal: 100, FirstSeen: now},
			{PID: 2, RemoteAddr: "2.2.2.2", RemotePort: 80, Proto: "tcp", BytesInTotal: 300, FirstSeen: now},
		},
	}

	state := newMetricsState(now)
	md := state.buildMetrics(snap, now, cfg)

	m := findMetric(md, metadata.MetricNetworkIO)
	if m == nil {
		t.Fatal("metric not found")
	}

	overflow, ok := findDataPoint(m.Sum().DataPoints(), map[string]any{
		metadata.AttrPeerOverflow:       true,
		metadata.AttrNetworkIODirection: metadata.AttrDirectionReceive,
	})
	if !ok {
		t.Fatal("overflow data point not found")
	}
	if overflow.IntValue() != 300 {
		t.Errorf("overflow receive bytes = %d, want 300 (the one connection past the cap)", overflow.IntValue())
	}

	// Second tick with the same totals: the overflow bucket must not
	// double-count, since it's a cumulative sum advancing by delta.
	md2 := state.buildMetrics(snap, now.Add(time.Second), cfg)
	m2 := findMetric(md2, metadata.MetricNetworkIO)
	overflow2, ok := findDataPoint(m2.Sum().DataPoints(), map[string]any{
		metadata.AttrPeerOverflow: true, metadata.AttrNetworkIODirection: metadata.AttrDirectionReceive,
	})
	if !ok {
		t.Fatal("overflow data point not found on second tick")
	}
	if overflow2.IntValue() != 300 {
		t.Errorf("overflow receive bytes on second tick = %d, want 300 (unchanged totals)", overflow2.IntValue())
	}
}

func TestBuildMetricsDNSQueryCount(t *testing.T) {
	now := time.Now()
	cfg := NewDefaultConfig()
	state := newMetricsState(now)

	snap := aggregate.Snapshot{
		DNSQueries: []dpi.QueryFinding{
			{Name: "example.com.", QType: "A", ClientAddr: "10.0.0.5", ServerAddr: "8.8.8.8", At: now},
			{Name: "example.com.", QType: "A", ClientAddr: "10.0.0.5", ServerAddr: "8.8.8.8", At: now},
		},
	}

	md := state.buildMetrics(snap, now, cfg)
	m := findMetric(md, metadata.MetricDNSQueryCount)
	if m == nil {
		t.Fatal("trafficmon.dns.query.count metric not found")
	}
	dp, ok := findDataPoint(m.Sum().DataPoints(), map[string]any{
		"dns.question.name":          "example.com.",
		metadata.AttrDNSQuestionType: "A",
	})
	if !ok {
		t.Fatal("data point not found")
	}
	if dp.IntValue() != 2 {
		t.Errorf("count = %d, want 2", dp.IntValue())
	}

	// A second tick with one more query for the same name must accumulate,
	// since the metric is a cumulative running total, not a per-tick count.
	md2 := state.buildMetrics(aggregate.Snapshot{
		DNSQueries: []dpi.QueryFinding{{Name: "example.com.", QType: "A", At: now}},
	}, now.Add(time.Second), cfg)
	m2 := findMetric(md2, metadata.MetricDNSQueryCount)
	dp2, ok := findDataPoint(m2.Sum().DataPoints(), map[string]any{"dns.question.name": "example.com."})
	if !ok {
		t.Fatal("data point not found on second tick")
	}
	if dp2.IntValue() != 3 {
		t.Errorf("cumulative count = %d, want 3", dp2.IntValue())
	}
}

func TestBuildMetricsSYNCount(t *testing.T) {
	now := time.Now()
	cfg := NewDefaultConfig()
	state := newMetricsState(now)

	ev := capture.SYNEvent{
		Iface:      "en0",
		LocalAddr:  netip.MustParseAddr("10.0.0.5"),
		LocalPort:  51000,
		RemoteAddr: netip.MustParseAddr("93.184.216.34"),
		RemotePort: 443,
		At:         now,
	}
	snap := aggregate.Snapshot{SYNEvents: []capture.SYNEvent{ev, ev}}

	md := state.buildMetrics(snap, now, cfg)
	m := findMetric(md, metadata.MetricNetworkSYNCount)
	if m == nil {
		t.Fatal("trafficmon.network.syn.count metric not found")
	}
	dp, ok := findDataPoint(m.Sum().DataPoints(), map[string]any{
		"network.peer.address":            "93.184.216.34",
		"network.peer.port":               int64(443),
		metadata.AttrNetworkInterfaceName: "en0",
	})
	if !ok {
		t.Fatal("data point not found")
	}
	if dp.IntValue() != 2 {
		t.Errorf("count = %d, want 2", dp.IntValue())
	}
}

func TestBuildLogsDNSQuery(t *testing.T) {
	now := time.Now()
	snap := aggregate.Snapshot{
		Connections: []aggregate.ConnectionRecord{
			{PID: 999, LocalAddr: "10.0.0.5", LocalPort: 55000},
		},
		DNSQueries: []dpi.QueryFinding{
			{Name: "example.com.", QType: "A", ClientAddr: "10.0.0.5", ServerAddr: "8.8.8.8", At: now},
		},
	}

	ld := buildLogs(snap, now, newSYNAttemptCache())
	records := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	if records.Len() != 1 {
		t.Fatalf("log record count = %d, want 1", records.Len())
	}
	lr := records.At(0)
	if lr.Body().Str() != "example.com." {
		t.Errorf("body = %q, want %q", lr.Body().Str(), "example.com.")
	}
	if got, _ := lr.Attributes().Get("network.peer.address"); got.Str() != "8.8.8.8" {
		t.Errorf("network.peer.address = %q, want 8.8.8.8", got.Str())
	}
	if got, ok := lr.Attributes().Get("network.local.address"); !ok || got.Str() != "10.0.0.5" {
		t.Errorf("network.local.address = %q, ok=%v, want 10.0.0.5", got.Str(), ok)
	}
}

func TestBuildLogsDNSQueryUnattributed(t *testing.T) {
	now := time.Now()
	snap := aggregate.Snapshot{
		DNSQueries: []dpi.QueryFinding{
			{Name: "example.com.", QType: "A", ClientAddr: "10.0.0.9", ServerAddr: "8.8.8.8", At: now},
		},
	}

	ld := buildLogs(snap, now, newSYNAttemptCache())
	lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	if _, ok := lr.Attributes().Get("network.local.address"); ok {
		t.Error("network.local.address should be omitted when no connection matches the client address")
	}
}

func TestBuildLogsSYN(t *testing.T) {
	now := time.Now()
	ev := capture.SYNEvent{
		Iface:      "en0",
		LocalAddr:  netip.MustParseAddr("10.0.0.5"),
		LocalPort:  51000,
		RemoteAddr: netip.MustParseAddr("93.184.216.34"),
		RemotePort: 443,
		At:         now,
	}
	ld := buildLogs(aggregate.Snapshot{SYNEvents: []capture.SYNEvent{ev}}, now, newSYNAttemptCache())
	records := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	if records.Len() != 1 {
		t.Fatalf("log record count = %d, want 1", records.Len())
	}
	lr := records.At(0)
	if _, ok := lr.Attributes().Get("process.pid"); ok {
		t.Error("SYN log record must carry no PID attribution")
	}
	if got, _ := lr.Attributes().Get("network.local.port"); got.Int() != 51000 {
		t.Errorf("network.local.port = %d, want 51000", got.Int())
	}
	if got, _ := lr.Attributes().Get(metadata.AttrSYNAttemptCount); got.Int() != 1 {
		t.Errorf("%s = %d, want 1 on first sighting", metadata.AttrSYNAttemptCount, got.Int())
	}
}

// TestBuildLogsSYNAttemptCount drives buildLogs across several ticks sharing
// one synAttemptCache, as collect() does, and checks the attempt count it
// attaches tracks repeats to the same 4-tuple, stays independent per
// 4-tuple, and forgets attempts once they've aged out of synAttemptWindow.
func TestBuildLogsSYNAttemptCount(t *testing.T) {
	cache := newSYNAttemptCache()
	base := time.Now()
	same := capture.SYNEvent{
		Iface: "en0", LocalAddr: netip.MustParseAddr("10.0.0.5"), LocalPort: 51000,
		RemoteAddr: netip.MustParseAddr("93.184.216.34"), RemotePort: 443,
	}
	other := same
	other.RemotePort = 8443

	attemptCount := func(ev capture.SYNEvent, now time.Time) int64 {
		ld := buildLogs(aggregate.Snapshot{SYNEvents: []capture.SYNEvent{ev}}, now, cache)
		lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		got, _ := lr.Attributes().Get(metadata.AttrSYNAttemptCount)
		return got.Int()
	}

	same.At = base
	if got := attemptCount(same, base); got != 1 {
		t.Errorf("1st attempt count = %d, want 1", got)
	}

	other.At = base.Add(time.Second)
	if got := attemptCount(other, other.At); got != 1 {
		t.Errorf("different 4-tuple's count = %d, want 1 (independent of same)", got)
	}

	same.At = base.Add(2 * time.Second)
	if got := attemptCount(same, same.At); got != 2 {
		t.Errorf("2nd attempt on same 4-tuple = %d, want 2", got)
	}

	// Far enough past the 2nd attempt (base+2s) that both it and the 1st
	// (base+0s) have aged out of the window, leaving only this one.
	same.At = base.Add(2*time.Second + synAttemptWindow + 10*time.Second)
	if got := attemptCount(same, same.At); got != 1 {
		t.Errorf("attempt count after window elapsed = %d, want 1 (earlier attempts aged out)", got)
	}
}
