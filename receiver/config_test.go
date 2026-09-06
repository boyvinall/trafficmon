package trafficmonreceiver

import (
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"defaults", *NewDefaultConfig(), false},
		{"zero collection interval", Config{CollectionInterval: 0, MaxPeerCardinality: 1}, true},
		{"negative collection interval", Config{CollectionInterval: -time.Second, MaxPeerCardinality: 1}, true},
		{"zero max peer cardinality", Config{CollectionInterval: time.Second, MaxPeerCardinality: 0}, true},
		{"negative max peer cardinality", Config{CollectionInterval: time.Second, MaxPeerCardinality: -1}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
