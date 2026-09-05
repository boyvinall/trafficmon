//go:build linux

package procinfo

import "log/slog"

// NewBestSource picks the best available ConnectionSource: the eBPF event
// stream if it can attach, falling back to the procfs Poller on any error
// (missing BTF, no kprobe support, permission denied, etc.) -- eBPF is
// never a hard requirement, since Poller must always remain available as
// the guaranteed last resort.
func NewBestSource() Source {
	src, err := NewEBPFSource()
	if err != nil {
		slog.Warn("procinfo: eBPF backend unavailable, falling back to procfs poller", "error", err)
		return NewPoller()
	}
	return src
}
