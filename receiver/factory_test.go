package trafficmonreceiver

import (
	"context"
	"testing"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver"

	"github.com/boyvinall/trafficmon/receiver/internal/metadata"
)

func testSettings() receiver.Settings {
	return receiver.Settings{
		ID:                component.NewID(metadata.Type),
		TelemetrySettings: componenttest.NewNopTelemetrySettings(),
		BuildInfo:         component.NewDefaultBuildInfo(),
	}
}

func TestNewFactory(t *testing.T) {
	f := NewFactory()
	if f.Type() != metadata.Type {
		t.Errorf("Type() = %v, want %v", f.Type(), metadata.Type)
	}
	cfg := f.CreateDefaultConfig()
	if err := cfg.(*Config).Validate(); err != nil {
		t.Errorf("default config invalid: %v", err)
	}
}

// TestSharesInstanceAcrossSignals asserts that CreateMetrics and CreateLogs
// for the same *Config share one trafficmonReceiver, not two independent
// engines each opening their own capture handle.
func TestSharesInstanceAcrossSignals(t *testing.T) {
	f := NewFactory()
	cfg := f.CreateDefaultConfig().(*Config)

	metricsRecv, err := f.CreateMetrics(context.Background(), testSettings(), cfg, consumertest.NewNop())
	if err != nil {
		t.Fatalf("CreateMetrics: %v", err)
	}
	logsRecv, err := f.CreateLogs(context.Background(), testSettings(), cfg, consumertest.NewNop())
	if err != nil {
		t.Fatalf("CreateLogs: %v", err)
	}

	m, ok := metricsRecv.(sharedComponent)
	if !ok {
		t.Fatalf("CreateMetrics returned %T, want sharedComponent", metricsRecv)
	}
	l, ok := logsRecv.(sharedComponent)
	if !ok {
		t.Fatalf("CreateLogs returned %T, want sharedComponent", logsRecv)
	}
	if m.trafficmonReceiver != l.trafficmonReceiver {
		t.Error("CreateMetrics and CreateLogs for the same config did not share one trafficmonReceiver")
	}

	instancesMu.Lock()
	_, tracked := instances[cfg]
	instancesMu.Unlock()
	if !tracked {
		t.Error("shared instance not tracked in the factory's instance map")
	}
}
