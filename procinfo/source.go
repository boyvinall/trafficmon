package procinfo

import "context"

// ConnectionSource is anything that can report the currently open connections,
// satisfied today by *Poller and, on Linux, the eBPF-backed EBPFSource.
type ConnectionSource interface {
	Connections() []Connection
}

// Source is a ConnectionSource that also owns a background run loop --
// Poller's periodic /proc scan, or EBPFSource's ring-buffer consumer.
// NewBestSource returns one of these so cmd/trafficmon can drive whichever
// backend it picked the same way, without knowing which one it got.
type Source interface {
	ConnectionSource
	Run(ctx context.Context) error
}
