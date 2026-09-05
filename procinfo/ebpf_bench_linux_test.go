//go:build linux

package procinfo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
)

// BenchmarkEBPF drives EBPFSource's steady-state ring-buffer consumption
// against synthetic connection churn (see runChurn in churn_bench_test.go)
// at churnRates (50/200/500 conns/sec), reporting CPU user+sys (via
// syscall.Getrusage), events processed (EventCount) and connections still
// open at the end, alongside testing.B's own timing.
//
// Gated the same way procinfo/libproc_linux_test.go and capture/pcap_test.go
// gate their own root/live-resource-needing tests: CI has neither the
// privileges nor the BTF this needs.
func BenchmarkEBPF(b *testing.B) {
	if testing.Short() {
		b.Skip("attaches real eBPF programs")
	}
	if os.Geteuid() != 0 {
		b.Skip("attaching eBPF programs needs root")
	}

	for _, rate := range churnRates {
		b.Run(fmt.Sprintf("%dconns_sec", rate), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				benchmarkEBPFOnce(b, rate)
			}
		})
	}
}

func benchmarkEBPFOnce(b *testing.B, rate int) {
	b.Helper()

	src, err := NewEBPFSource()
	if err != nil {
		b.Skipf("eBPF backend unavailable: %v", err)
	}

	before := getrusageSelf(b)

	ctx, cancel := context.WithTimeout(context.Background(), benchDuration)
	defer cancel()

	churned := make(chan int, 1)
	go func() { churned <- runChurn(ctx, b, rate) }()

	if err := src.Run(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		b.Fatalf("ebpf source run: %v", err)
	}

	after := getrusageSelf(b)
	total := <-churned

	b.ReportMetric(cpuSeconds(&after)-cpuSeconds(&before), "cpu-sec")
	b.ReportMetric(float64(total), "conns-churned")
	b.ReportMetric(float64(src.EventCount()), "events-seen")
	b.ReportMetric(float64(len(src.Connections())), "conns-open-at-end")
}
