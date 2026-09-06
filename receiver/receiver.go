// Package trafficmonreceiver is an OpenTelemetry Collector receiver that
// wraps trafficmon's engine (capture.Capturer + a procinfo poller, joined by
// aggregate.Aggregator — the same wiring cmd/trafficmon's main.go uses) and
// turns each aggregate.Snapshot into metrics and logs.
package trafficmonreceiver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/boyvinall/trafficmon/aggregate"
	"github.com/boyvinall/trafficmon/capture"
	"github.com/boyvinall/trafficmon/dpi"
	"github.com/boyvinall/trafficmon/procinfo"
)

// trafficmonReceiver is shared between the metrics and logs signals: the
// collector core calls createMetricsReceiver/createLogsReceiver once each
// for the same configured component ID, and both must drive the same
// capture handle and procinfo poller rather than each opening their own —
// two live pcap handles on the same interface would mean the SYN/DNS-query
// ring buffers (see capture.Capturer.DrainSYNEvents/DrainDNSQueries) are
// only ever drained by whichever signal happens to poll first, silently
// starving the other.
type trafficmonReceiver struct {
	cfg    *Config
	logger *zap.Logger

	mu              sync.Mutex
	metricsConsumer consumer.Metrics
	logsConsumer    consumer.Logs
	refs            int
	cancel          context.CancelFunc
	wg              sync.WaitGroup

	// pidMu guards pidByLocalAddr, published wholesale by collect after
	// each Refresh and read by forwardLogs — its own mutex, per this
	// repo's convention for every shared map, rather than piggybacking on
	// mu (which guards consumer/lifecycle state instead).
	pidMu          sync.Mutex
	pidByLocalAddr map[string]int32
}

func newTrafficmonReceiver(set receiver.Settings, cfg *Config) *trafficmonReceiver {
	return &trafficmonReceiver{cfg: cfg, logger: set.Logger}
}

// Start implements component.Component. It is called once per signal
// (metrics, logs) sharing this instance; only the first call actually opens
// the capture handle and starts the poller and collection loop, which
// deliberately runs on its own long-lived context rather than Start's —
// the collector core only guarantees Start's ctx is valid for this call.
//
//nolint:contextcheck // see above
func (r *trafficmonReceiver) Start(_ context.Context, _ component.Host) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.refs++
	if r.refs > 1 {
		return nil
	}

	iface := r.cfg.Interface
	if iface == "" {
		var err error
		if iface, err = capture.DefaultInterface(); err != nil { //nolint:contextcheck // DefaultInterface deliberately owns its own short, fixed timeout rather than ctx's
			r.refs--
			return fmt.Errorf("detect interface: %w", err)
		}
	}

	capCfg := capture.DefaultConfig()
	capCfg.Interface = iface
	capCfg.IncludeLoopback = r.cfg.IncludeLoopback
	capCfg.EnableLogFeed = r.logsConsumer != nil

	capturer := capture.New(capCfg)
	source := procinfo.NewBestSource()
	agg := aggregate.New(capturer, source)

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return capturer.Run(gctx) })
	g.Go(func() error { return source.Run(gctx) })

	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.Error("trafficmon engine stopped", zap.Error(err))
		}
	}()
	go func() {
		defer r.wg.Done()
		r.collect(ctx, agg)
	}()

	if r.logsConsumer != nil {
		r.wg.Add(1)
		logsConsumer := r.logsConsumer
		go func() {
			defer r.wg.Done()
			r.forwardLogs(ctx, capturer, logsConsumer)
		}()
	}

	return nil
}

// collect ticks at cfg.CollectionInterval, translating each
// aggregate.Snapshot into metrics for the metrics consumer, if set. It also
// republishes pidByLocalAddr after every Refresh for forwardLogs to consult
// — logs delivery itself is handled by forwardLogs, off capturer's own
// streaming feed, not by this tick.
func (r *trafficmonReceiver) collect(ctx context.Context, agg *aggregate.Aggregator) {
	ticker := time.NewTicker(r.cfg.CollectionInterval)
	defer ticker.Stop()

	state := newMetricsState(time.Now())

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		now := time.Now()
		snap := agg.Refresh(now)
		r.publishPidByLocalAddr(pidByLocalAddrFrom(snap.Connections))

		r.mu.Lock()
		metricsConsumer := r.metricsConsumer
		r.mu.Unlock()

		if metricsConsumer != nil {
			if err := metricsConsumer.ConsumeMetrics(ctx, state.buildMetrics(snap, now, r.cfg)); err != nil {
				r.logger.Error("consume metrics", zap.Error(err))
			}
		}
	}
}

// publishPidByLocalAddr replaces pidByLocalAddr wholesale — never patched in
// place, so a reader in forwardLogs always sees either the previous
// snapshot or the new one, never a partially-updated map.
func (r *trafficmonReceiver) publishPidByLocalAddr(m map[string]int32) {
	r.pidMu.Lock()
	r.pidByLocalAddr = m
	r.pidMu.Unlock()
}

// currentPidByLocalAddr returns the map most recently published by collect.
func (r *trafficmonReceiver) currentPidByLocalAddr() map[string]int32 {
	r.pidMu.Lock()
	defer r.pidMu.Unlock()
	return r.pidByLocalAddr
}

// logFlushInterval bounds how long a SYN/DNS-query log record can sit in
// forwardLogs's pending batch before being exported — it governs export
// call frequency and latency only, unlike collect's ticker, which also
// gates when an event is picked up at all.
const logFlushInterval = 200 * time.Millisecond

// logBatchCap flushes forwardLogs's pending batch early, ahead of
// logFlushInterval, once it grows this large — bounding one export call's
// size during a sustained burst rather than growing it unbounded until the
// next tick.
const logBatchCap = 500

// logFeedSource is the slice of *capture.Capturer forwardLogs depends on —
// narrowed to an interface so a test can drive forwardLogs off channels it
// controls directly, without a live pcap handle.
type logFeedSource interface {
	LogFeed() (syn <-chan capture.SYNEvent, dnsQuery <-chan dpi.QueryFinding, ok bool)
	LogFeedOverflow() (syn, dnsQuery uint64)
}

// forwardLogs streams SYN/DNS-query events from source's non-blocking log
// feed to logsConsumer as they occur, batched only enough to bound export
// call frequency (logFlushInterval) and size (logBatchCap) — unlike
// collect's metrics tick, an event's delivery latency is not tied to
// cfg.CollectionInterval. It returns once ctx is cancelled, or immediately
// if source's log feed isn't enabled.
func (r *trafficmonReceiver) forwardLogs(ctx context.Context, source logFeedSource, logsConsumer consumer.Logs) {
	synCh, dnsCh, ok := source.LogFeed()
	if !ok {
		return
	}

	synAttempts := newSYNAttemptCache()
	flushTicker := time.NewTicker(logFlushInterval)
	defer flushTicker.Stop()

	var pendingSYN []capture.SYNEvent
	var pendingDNS []dpi.QueryFinding
	var lastSYNOverflow, lastDNSOverflow uint64

	flush := func() {
		if len(pendingSYN) == 0 && len(pendingDNS) == 0 {
			return
		}
		batch := buildLogBatch(pendingSYN, pendingDNS, time.Now(), synAttempts, r.currentPidByLocalAddr())
		pendingSYN, pendingDNS = nil, nil
		if err := logsConsumer.ConsumeLogs(ctx, batch); err != nil {
			r.logger.Error("consume logs", zap.Error(err))
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-synCh:
			pendingSYN = append(pendingSYN, ev)
			if len(pendingSYN)+len(pendingDNS) >= logBatchCap {
				flush()
			}
		case q := <-dnsCh:
			pendingDNS = append(pendingDNS, q)
			if len(pendingSYN)+len(pendingDNS) >= logBatchCap {
				flush()
			}
		case <-flushTicker.C:
			flush()
			if syn, dnsQuery := source.LogFeedOverflow(); syn != lastSYNOverflow || dnsQuery != lastDNSOverflow {
				r.logger.Warn("dropped log events: consumer or channel too slow",
					zap.Uint64("syn_dropped", syn-lastSYNOverflow),
					zap.Uint64("dns_query_dropped", dnsQuery-lastDNSOverflow))
				lastSYNOverflow, lastDNSOverflow = syn, dnsQuery
			}
		}
	}
}

// refCount returns how many signals are still holding this instance open.
func (r *trafficmonReceiver) refCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refs
}

// Shutdown implements component.Component. The underlying engine and
// collection loop stop only once every signal sharing this instance has
// shut down.
func (r *trafficmonReceiver) Shutdown(_ context.Context) error {
	r.mu.Lock()
	r.refs--
	done := r.refs == 0
	cancel := r.cancel
	r.mu.Unlock()

	if !done || cancel == nil {
		return nil
	}
	cancel()
	r.wg.Wait()
	return nil
}
