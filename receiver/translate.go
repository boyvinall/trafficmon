package trafficmonreceiver

import (
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/boyvinall/trafficmon/aggregate"
	"github.com/boyvinall/trafficmon/capture"
	"github.com/boyvinall/trafficmon/dpi"
	"github.com/boyvinall/trafficmon/receiver/internal/metadata"
)

// peerLimiter bounds the number of distinct (remote address, port) pairs
// that may carry their own attributes within one collection interval — the
// receiver-side cardinality cap config.Config.MaxPeerCardinality controls.
// It is shared across every metric that carries a peer address/port within
// one tick, since the cap is meant to bound total peer cardinality for the
// interval as a whole, not per metric.
type peerLimiter struct {
	max  int
	seen map[string]struct{}
}

func newPeerLimiter(maxPeers int) *peerLimiter {
	return &peerLimiter{max: maxPeers, seen: make(map[string]struct{})}
}

// allow reports whether addr:port may carry its own peer attributes this
// interval, as opposed to folding into the shared overflow bucket.
func (l *peerLimiter) allow(addr string, port uint16) bool {
	key := fmt.Sprintf("%s:%d", addr, port)
	if _, ok := l.seen[key]; ok {
		return true
	}
	if len(l.seen) >= l.max {
		return false
	}
	l.seen[key] = struct{}{}
	return true
}

// flowIdentity names one connection stably across ticks, for metricsState's
// per-flow bookkeeping — the same fields aggregate.connKey uses internally,
// rebuilt here since that type isn't exported.
type flowIdentity struct {
	pid                   int32
	localAddr, remoteAddr string
	localPort, remotePort uint16
	proto                 string
}

type ioTotals struct {
	in, out uint64
}

type dnsKey struct{ name, qtype string }

type dnsErrorKey struct{ name, qtype, rcode string }

type synKey struct {
	addr, iface string
	port        uint16
}

type rstKey struct {
	addr, iface string
	port        uint16
}

// metricsState carries the receiver-computed cumulative counters forward
// across collection ticks: DNS query and SYN counts have no running total
// of their own the way ConnectionRecord.BytesInTotal/BytesOutTotal do, so
// the receiver accumulates them itself, and the overflow buckets need a
// persistent total too so they stay genuinely monotonic even though which
// flows fall into them can shift from tick to tick.
type metricsState struct {
	start time.Time

	dnsCounts      map[dnsKey]uint64
	dnsErrorCounts map[dnsErrorKey]uint64
	synCounts      map[synKey]uint64
	rstCounts      map[rstKey]uint64

	synOverflowCount uint64
	rstOverflowCount uint64
	overflowBytesIn  uint64
	overflowBytesOut uint64

	// lastIO is the last-recorded BytesInTotal/BytesOutTotal for every
	// currently-overflowing flow, so overflowBytesIn/Out advance by the
	// delta since last tick rather than double-counting each flow's whole
	// running total every interval. Rebuilt wholesale each tick to the set
	// of flows actually seen, so a flow that stops overflowing (or closes)
	// doesn't linger in it forever.
	lastIO map[flowIdentity]ioTotals
}

func newMetricsState(start time.Time) *metricsState {
	return &metricsState{
		start:          start,
		dnsCounts:      make(map[dnsKey]uint64),
		dnsErrorCounts: make(map[dnsErrorKey]uint64),
		synCounts:      make(map[synKey]uint64),
		rstCounts:      make(map[rstKey]uint64),
		lastIO:         make(map[flowIdentity]ioTotals),
	}
}

// buildMetrics translates one aggregate.Snapshot into the three
// trafficmon.* cumulative sums, advancing s's persistent counters in the
// process.
func (s *metricsState) buildMetrics(snap aggregate.Snapshot, now time.Time, cfg *Config) pmetric.Metrics {
	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(metadata.ScopeName)

	limiter := newPeerLimiter(cfg.MaxPeerCardinality)

	ioMetric := sm.Metrics().AppendEmpty()
	ioMetric.SetName(metadata.MetricNetworkIO)
	ioMetric.SetUnit("By")
	ioSum := ioMetric.SetEmptySum()
	ioSum.SetIsMonotonic(true)
	ioSum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)

	nextLastIO := make(map[flowIdentity]ioTotals, len(s.lastIO))
	var overflowed bool

	for _, rec := range snap.Connections {
		id := flowIdentity{
			pid:        rec.PID,
			localAddr:  rec.LocalAddr,
			localPort:  rec.LocalPort,
			remoteAddr: rec.RemoteAddr,
			remotePort: rec.RemotePort,
			proto:      rec.Proto,
		}

		if limiter.allow(rec.RemoteAddr, rec.RemotePort) {
			addIODataPoint(ioSum.DataPoints(), rec, now)
			continue
		}

		overflowed = true
		prev := s.lastIO[id]
		if rec.BytesInTotal > prev.in {
			s.overflowBytesIn += rec.BytesInTotal - prev.in
		}
		if rec.BytesOutTotal > prev.out {
			s.overflowBytesOut += rec.BytesOutTotal - prev.out
		}
		nextLastIO[id] = ioTotals{in: rec.BytesInTotal, out: rec.BytesOutTotal}
	}
	s.lastIO = nextLastIO

	if overflowed {
		addOverflowIODataPoints(ioSum.DataPoints(), s.start, now, s.overflowBytesIn, s.overflowBytesOut)
	}

	for _, q := range snap.DNSQueries {
		s.dnsCounts[dnsKey{name: q.Name, qtype: q.QType}]++
	}
	if len(snap.DNSQueries) > 0 {
		dnsMetric := sm.Metrics().AppendEmpty()
		dnsMetric.SetName(metadata.MetricDNSQueryCount)
		dnsMetric.SetUnit("{query}")
		dnsSum := dnsMetric.SetEmptySum()
		dnsSum.SetIsMonotonic(true)
		dnsSum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)

		seen := make(map[dnsKey]struct{}, len(snap.DNSQueries))
		for _, q := range snap.DNSQueries {
			k := dnsKey{name: q.Name, qtype: q.QType}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			dp := dnsSum.DataPoints().AppendEmpty()
			dp.SetStartTimestamp(pcommon.NewTimestampFromTime(s.start))
			dp.SetTimestamp(pcommon.NewTimestampFromTime(now))
			dp.SetIntValue(int64(s.dnsCounts[k]))
			dp.Attributes().PutStr("dns.question.name", k.name)
			dp.Attributes().PutStr(metadata.AttrDNSQuestionType, k.qtype)
		}
	}

	for _, e := range snap.DNSErrors {
		s.dnsErrorCounts[dnsErrorKey{name: e.Name, qtype: e.QType, rcode: e.RCode}]++
	}
	if len(snap.DNSErrors) > 0 {
		dnsErrMetric := sm.Metrics().AppendEmpty()
		dnsErrMetric.SetName(metadata.MetricDNSQueryErrors)
		dnsErrMetric.SetUnit("{query}")
		dnsErrSum := dnsErrMetric.SetEmptySum()
		dnsErrSum.SetIsMonotonic(true)
		dnsErrSum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)

		seen := make(map[dnsErrorKey]struct{}, len(snap.DNSErrors))
		for _, e := range snap.DNSErrors {
			k := dnsErrorKey{name: e.Name, qtype: e.QType, rcode: e.RCode}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			dp := dnsErrSum.DataPoints().AppendEmpty()
			dp.SetStartTimestamp(pcommon.NewTimestampFromTime(s.start))
			dp.SetTimestamp(pcommon.NewTimestampFromTime(now))
			dp.SetIntValue(int64(s.dnsErrorCounts[k]))
			dp.Attributes().PutStr("dns.question.name", k.name)
			dp.Attributes().PutStr(metadata.AttrDNSQuestionType, k.qtype)
			dp.Attributes().PutStr(metadata.AttrDNSResponseCode, k.rcode)
		}
	}

	touchedSYN := make(map[synKey]struct{}, len(snap.SYNEvents))
	for _, ev := range snap.SYNEvents {
		if limiter.allow(ev.RemoteAddr.String(), ev.RemotePort) {
			k := synKey{addr: ev.RemoteAddr.String(), port: ev.RemotePort, iface: ev.Iface}
			s.synCounts[k]++
			touchedSYN[k] = struct{}{}
			continue
		}
		s.synOverflowCount++
	}
	if len(snap.SYNEvents) > 0 {
		synMetric := sm.Metrics().AppendEmpty()
		synMetric.SetName(metadata.MetricNetworkSYNCount)
		synMetric.SetUnit("{attempt}")
		synSum := synMetric.SetEmptySum()
		synSum.SetIsMonotonic(true)
		synSum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)

		for k := range touchedSYN {
			dp := synSum.DataPoints().AppendEmpty()
			dp.SetStartTimestamp(pcommon.NewTimestampFromTime(s.start))
			dp.SetTimestamp(pcommon.NewTimestampFromTime(now))
			dp.SetIntValue(int64(s.synCounts[k]))
			dp.Attributes().PutStr("network.peer.address", k.addr)
			dp.Attributes().PutInt("network.peer.port", int64(k.port))
			dp.Attributes().PutStr(metadata.AttrNetworkInterfaceName, k.iface)
		}
		if s.synOverflowCount > 0 {
			dp := synSum.DataPoints().AppendEmpty()
			dp.SetStartTimestamp(pcommon.NewTimestampFromTime(s.start))
			dp.SetTimestamp(pcommon.NewTimestampFromTime(now))
			dp.SetIntValue(int64(s.synOverflowCount))
			dp.Attributes().PutBool(metadata.AttrPeerOverflow, true)
		}
	}

	touchedRST := make(map[rstKey]struct{}, len(snap.RSTEvents))
	for _, ev := range snap.RSTEvents {
		if limiter.allow(ev.RemoteAddr.String(), ev.RemotePort) {
			k := rstKey{addr: ev.RemoteAddr.String(), port: ev.RemotePort, iface: ev.Iface}
			s.rstCounts[k]++
			touchedRST[k] = struct{}{}
			continue
		}
		s.rstOverflowCount++
	}
	if len(snap.RSTEvents) > 0 {
		rstMetric := sm.Metrics().AppendEmpty()
		rstMetric.SetName(metadata.MetricNetworkRSTCount)
		rstMetric.SetUnit("{reset}")
		rstSum := rstMetric.SetEmptySum()
		rstSum.SetIsMonotonic(true)
		rstSum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)

		for k := range touchedRST {
			dp := rstSum.DataPoints().AppendEmpty()
			dp.SetStartTimestamp(pcommon.NewTimestampFromTime(s.start))
			dp.SetTimestamp(pcommon.NewTimestampFromTime(now))
			dp.SetIntValue(int64(s.rstCounts[k]))
			dp.Attributes().PutStr("network.peer.address", k.addr)
			dp.Attributes().PutInt("network.peer.port", int64(k.port))
			dp.Attributes().PutStr(metadata.AttrNetworkInterfaceName, k.iface)
		}
		if s.rstOverflowCount > 0 {
			dp := rstSum.DataPoints().AppendEmpty()
			dp.SetStartTimestamp(pcommon.NewTimestampFromTime(s.start))
			dp.SetTimestamp(pcommon.NewTimestampFromTime(now))
			dp.SetIntValue(int64(s.rstOverflowCount))
			dp.Attributes().PutBool(metadata.AttrPeerOverflow, true)
		}
	}

	if len(snap.PacketStats) > 0 {
		droppedMetric := sm.Metrics().AppendEmpty()
		droppedMetric.SetName(metadata.MetricCapturePacketsDropped)
		droppedMetric.SetUnit("{packet}")
		droppedSum := droppedMetric.SetEmptySum()
		droppedSum.SetIsMonotonic(true)
		droppedSum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)

		for iface, stats := range snap.PacketStats {
			dp := droppedSum.DataPoints().AppendEmpty()
			dp.SetStartTimestamp(pcommon.NewTimestampFromTime(s.start))
			dp.SetTimestamp(pcommon.NewTimestampFromTime(now))
			dp.SetIntValue(int64(stats.Dropped))
			dp.Attributes().PutStr(metadata.AttrNetworkInterfaceName, iface)
		}
	}

	return md
}

// addIODataPoint appends one MetricNetworkIO transmit and one receive data
// point for rec to points.
func addIODataPoint(points pmetric.NumberDataPointSlice, rec aggregate.ConnectionRecord, now time.Time) {
	for _, d := range [...]struct {
		direction string
		bytes     uint64
	}{
		{metadata.AttrDirectionTransmit, rec.BytesOutTotal},
		{metadata.AttrDirectionReceive, rec.BytesInTotal},
	} {
		dp := points.AppendEmpty()
		dp.SetStartTimestamp(pcommon.NewTimestampFromTime(rec.FirstSeen))
		dp.SetTimestamp(pcommon.NewTimestampFromTime(now))
		dp.SetIntValue(int64(d.bytes))
		attrs := dp.Attributes()
		attrs.PutStr(metadata.AttrNetworkIODirection, d.direction)
		attrs.PutStr("network.transport", rec.Proto)
		if rec.Iface != "" {
			attrs.PutStr(metadata.AttrNetworkInterfaceName, rec.Iface)
		}
		attrs.PutStr("network.peer.address", rec.RemoteAddr)
		attrs.PutInt("network.peer.port", int64(rec.RemotePort))
		if rec.PID != 0 {
			attrs.PutInt("process.pid", int64(rec.PID))
			attrs.PutStr("process.executable.name", rec.ProcessName)
		}
	}
}

// addOverflowIODataPoints appends the single transmit/receive pair
// representing every connection folded into the cardinality-cap overflow
// bucket this tick.
func addOverflowIODataPoints(points pmetric.NumberDataPointSlice, start, now time.Time, bytesIn, bytesOut uint64) {
	for _, d := range [...]struct {
		direction string
		bytes     uint64
	}{
		{metadata.AttrDirectionTransmit, bytesOut},
		{metadata.AttrDirectionReceive, bytesIn},
	} {
		dp := points.AppendEmpty()
		dp.SetStartTimestamp(pcommon.NewTimestampFromTime(start))
		dp.SetTimestamp(pcommon.NewTimestampFromTime(now))
		dp.SetIntValue(int64(d.bytes))
		attrs := dp.Attributes()
		attrs.PutStr(metadata.AttrNetworkIODirection, d.direction)
		attrs.PutBool(metadata.AttrPeerOverflow, true)
	}
}

// buildLogs translates one aggregate.Snapshot's SYNEvents and DNSQueries
// into log records. snap.Connections is consulted only for the DNS query
// record's best-effort client-PID attribution. synAttempts carries the
// rolling per-4-tuple SYN counts across calls; its prune runs once per call
// so a 4-tuple that has stopped attempting eventually drops out.
func buildLogs(snap aggregate.Snapshot, now time.Time, synAttempts *synAttemptCache) plog.Logs {
	ld := plog.NewLogs()
	sl := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	sl.Scope().SetName(metadata.ScopeName)

	if len(snap.DNSQueries) > 0 || len(snap.SYNEvents) > 0 {
		// pidByLocalAddr maps a locally bound address to the PID currently
		// holding it, for DNSQueryFinding's client attribution below. It is
		// necessarily best-effort: procinfo's socket table is polled once a
		// second (see aggregate.GracePeriod's doc comment), so a DNS query's
		// outbound socket can easily open and close between polls with no
		// snapshot ever reporting it.
		pidByLocalAddr := make(map[string]int32, len(snap.Connections))
		for _, rec := range snap.Connections {
			pidByLocalAddr[rec.LocalAddr] = rec.PID
		}

		for _, q := range snap.DNSQueries {
			addDNSQueryLogRecord(sl.LogRecords(), q, now, pidByLocalAddr)
		}
		synAttempts.prune(now)
		for _, ev := range snap.SYNEvents {
			key := synAttemptKeyFor(ev)
			count := synAttempts.record(key, ev.At)
			addSYNLogRecord(sl.LogRecords(), ev, now, key, count)
		}
	}

	return ld
}

func addDNSQueryLogRecord(records plog.LogRecordSlice, q dpi.QueryFinding, now time.Time, pidByLocalAddr map[string]int32) {
	lr := records.AppendEmpty()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(q.At))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	lr.Body().SetStr(q.Name)

	attrs := lr.Attributes()
	attrs.PutStr("dns.question.name", q.Name)
	attrs.PutStr(metadata.AttrDNSQuestionType, q.QType)
	attrs.PutStr("network.peer.address", q.ServerAddr)
	if pid, ok := pidByLocalAddr[q.ClientAddr]; ok && pid != 0 {
		attrs.PutStr("network.local.address", q.ClientAddr)
	}
}

func addSYNLogRecord(records plog.LogRecordSlice, ev capture.SYNEvent, now time.Time, key synAttemptKey, attemptCount int) {
	lr := records.AppendEmpty()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(ev.At))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	lr.Body().SetStr(fmt.Sprintf("SYN %d %s (last %s)", attemptCount, key, synAttemptWindow))

	attrs := lr.Attributes()
	attrs.PutStr("network.peer.address", ev.RemoteAddr.String())
	attrs.PutInt("network.peer.port", int64(ev.RemotePort))
	attrs.PutStr(metadata.AttrNetworkInterfaceName, ev.Iface)
	attrs.PutInt("network.local.port", int64(ev.LocalPort))
	attrs.PutInt(metadata.AttrSYNAttemptCount, int64(attemptCount))
}
