package procinfo

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// BenchmarkPoller drives *procinfo.Poller's poll()/Run path against
// synthetic connection churn (see runChurn in churn_bench_test.go) at
// churnRates (50/200/500 conns/sec), reporting CPU user+sys (via
// syscall.Getrusage) and connection counts alongside testing.B's own
// timing. Unlike BenchmarkEBPF this needs no root/eBPF privileges and runs
// on every platform Poller supports, so it is not skip-gated.
func BenchmarkPoller(b *testing.B) {
	for _, rate := range churnRates {
		b.Run(fmt.Sprintf("%dconns_sec", rate), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				benchmarkPollerOnce(b, rate)
			}
		})
	}
}

func benchmarkPollerOnce(b *testing.B, rate int) {
	b.Helper()

	before := getrusageSelf(b)

	p := NewPoller()
	ctx, cancel := context.WithTimeout(context.Background(), benchDuration)
	defer cancel()

	churned := make(chan int, 1)
	go func() { churned <- runChurn(ctx, b, rate) }()

	if err := p.Run(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		b.Fatalf("poller run: %v", err)
	}

	after := getrusageSelf(b)
	total := <-churned
	conns := len(p.Connections())

	b.ReportMetric(cpuSeconds(&after)-cpuSeconds(&before), "cpu-sec")
	b.ReportMetric(float64(total), "conns-churned")
	b.ReportMetric(float64(conns), "conns-seen")
}
