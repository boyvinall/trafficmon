package trafficmonreceiver

import (
	"context"
	"sync"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"

	"github.com/boyvinall/trafficmon/receiver/internal/metadata"
)

// instances shares one trafficmonReceiver between the metrics and logs
// signals of the same configured component, keyed by the *Config pointer
// the collector core hands both create calls for one component ID — see
// trafficmonReceiver's doc comment for why they must share an engine
// instance rather than each starting their own.
var (
	instancesMu sync.Mutex
	instances   = make(map[*Config]*trafficmonReceiver)
)

// NewFactory creates a factory for the trafficmon receiver.
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		receiver.WithMetrics(createMetricsReceiver, metadata.MetricsStability),
		receiver.WithLogs(createLogsReceiver, metadata.LogsStability),
	)
}

func createDefaultConfig() component.Config {
	return NewDefaultConfig()
}

func sharedReceiver(set receiver.Settings, cfg *Config) *trafficmonReceiver {
	instancesMu.Lock()
	defer instancesMu.Unlock()

	r, ok := instances[cfg]
	if !ok {
		r = newTrafficmonReceiver(set, cfg)
		instances[cfg] = r
	}
	return r
}

func createMetricsReceiver(_ context.Context, set receiver.Settings, cfg component.Config, next consumer.Metrics) (receiver.Metrics, error) {
	typed := cfg.(*Config)
	r := sharedReceiver(set, typed)
	r.mu.Lock()
	r.metricsConsumer = next
	r.mu.Unlock()
	return sharedComponent{trafficmonReceiver: r, cfg: typed}, nil
}

func createLogsReceiver(_ context.Context, set receiver.Settings, cfg component.Config, next consumer.Logs) (receiver.Logs, error) {
	typed := cfg.(*Config)
	r := sharedReceiver(set, typed)
	r.mu.Lock()
	r.logsConsumer = next
	r.mu.Unlock()
	return sharedComponent{trafficmonReceiver: r, cfg: typed}, nil
}

// sharedComponent wraps a *trafficmonReceiver just to drop it from the
// shared-instance map once its last reference shuts down; the receiver
// itself doesn't know about the map, only the factory that populates it.
type sharedComponent struct {
	*trafficmonReceiver
	cfg *Config
}

func (s sharedComponent) Shutdown(ctx context.Context) error {
	err := s.trafficmonReceiver.Shutdown(ctx)

	instancesMu.Lock()
	if s.refCount() == 0 {
		delete(instances, s.cfg)
	}
	instancesMu.Unlock()

	return err
}
