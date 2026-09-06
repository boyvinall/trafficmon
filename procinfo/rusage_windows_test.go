//go:build windows

package procinfo

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// cpuUsage is the Windows analogue of a syscall.Rusage snapshot: combined
// kernel+user CPU time, in nanoseconds.
type cpuUsage struct {
	ns int64
}

// cpuSeconds converts a cpuUsage snapshot's combined CPU time to seconds.
func cpuSeconds(cu *cpuUsage) float64 {
	return float64(cu.ns) / float64(time.Second)
}

// getrusageSelf is a small helper so both benchmarks capture the process's
// own CPU time the same way and fail the same way on error.
func getrusageSelf(tb testing.TB) cpuUsage {
	tb.Helper()
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		tb.Fatalf("GetProcessTimes: %v", err)
	}
	return cpuUsage{ns: kernel.Nanoseconds() + user.Nanoseconds()}
}
