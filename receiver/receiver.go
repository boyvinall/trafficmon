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

	return nil
}

// collect ticks at cfg.CollectionInterval, translating each
// aggregate.Snapshot into metrics/logs for whichever consumers are set.
func (r *trafficmonReceiver) collect(ctx context.Context, agg *aggregate.Aggregator) {
	ticker := time.NewTicker(r.cfg.CollectionInterval)
	defer ticker.Stop()

	state := newMetricsState(time.Now())
	synAttempts := newSYNAttemptCache()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		now := time.Now()
		snap := agg.Refresh(now)

		r.mu.Lock()
		metricsConsumer, logsConsumer := r.metricsConsumer, r.logsConsumer
		r.mu.Unlock()

		if metricsConsumer != nil {
			if err := metricsConsumer.ConsumeMetrics(ctx, state.buildMetrics(snap, now, r.cfg)); err != nil {
				r.logger.Error("consume metrics", zap.Error(err))
			}
		}
		if logsConsumer != nil {
			if err := logsConsumer.ConsumeLogs(ctx, buildLogs(snap, now, synAttempts)); err != nil {
				r.logger.Error("consume logs", zap.Error(err))
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
