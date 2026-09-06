//go:build !windows

package procinfo

import (
	"syscall"
	"testing"
	"time"
)

// cpuSeconds converts a syscall.Rusage snapshot's user+sys time to seconds.
func cpuSeconds(ru *syscall.Rusage) float64 {
	user := time.Duration(ru.Utime.Sec)*time.Second + time.Duration(ru.Utime.Usec)*time.Microsecond
	sys := time.Duration(ru.Stime.Sec)*time.Second + time.Duration(ru.Stime.Usec)*time.Microsecond
	return (user + sys).Seconds()
}

// getrusageSelf is a small helper so both benchmarks capture RUSAGE_SELF the
// same way and fail the same way on error.
func getrusageSelf(tb testing.TB) syscall.Rusage {
	tb.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		tb.Fatalf("getrusage: %v", err)
	}
	return ru
}
