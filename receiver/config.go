package trafficmonreceiver

import (
	"errors"
	"fmt"
	"time"
)

// Config configures the trafficmon receiver.
type Config struct {
	// CollectionInterval is how often the receiver polls the engine
	// (capture + procinfo) for a fresh aggregate.Snapshot.
	CollectionInterval time.Duration `mapstructure:"collection_interval"`

	// Interface is the network interface to capture on. Empty auto-detects
	// from the default route, the same as cmd/trafficmon.
	Interface string `mapstructure:"interface"`

	// IncludeLoopback also captures loopback traffic.
	IncludeLoopback bool `mapstructure:"include_loopback"`

	// MaxPeerCardinality caps the number of distinct (remote address, port)
	// attribute combinations emitted per collection interval. Raw per-flow
	// attribution is naturally high-cardinality — nothing in the engine
	// itself bounds it — so this is the receiver's own cutoff: past it,
	// further data points for that interval fold into a single overflow
	// series carrying metadata.AttrPeerOverflow="true" instead of their own
	// remote address/port.
	MaxPeerCardinality int `mapstructure:"max_peer_cardinality"`
}

// NewDefaultConfig returns the receiver defaults.
func NewDefaultConfig() *Config {
	return &Config{
		CollectionInterval: time.Second,
		MaxPeerCardinality: 1000,
	}
}

// Validate implements component.ConfigValidator.
func (c *Config) Validate() error {
	if c.CollectionInterval <= 0 {
		return errors.New("collection_interval must be positive")
	}
	if c.MaxPeerCardinality <= 0 {
		return fmt.Errorf("max_peer_cardinality must be positive, got %d", c.MaxPeerCardinality)
	}
	return nil
}
