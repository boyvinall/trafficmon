//go:build !linux

package procinfo

// NewBestSource always returns the procfs/libproc Poller: no eBPF backend
// exists outside Linux.
func NewBestSource() Source {
	return NewPoller()
}
