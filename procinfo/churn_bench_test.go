package procinfo

import (
	"context"
	"net"
	"testing"
	"time"
)

// benchDuration is how long each churn rate runs before CPU/connection
// counts are captured: a fixed wall-clock window per rate, short enough for
// CI/local runs.
const benchDuration = 5 * time.Second

// churnRates are the connection-churn rates exercised by both
// BenchmarkPoller and BenchmarkEBPF.
var churnRates = []int{50, 200, 500}

// runChurn generates local TCP connect/close churn at ratePerSec until ctx
// is done. It returns the number of connections successfully made.
func runChurn(ctx context.Context, tb testing.TB, ratePerSec int) int {
	tb.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("churn: listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.Close() }()
		}
	}()

	addr := ln.Addr().String()
	interval := time.Second / time.Duration(ratePerSec)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var total int
	for {
		select {
		case <-ctx.Done():
			return total
		case <-ticker.C:
			c, err := net.Dial("tcp", addr)
			if err != nil {
				continue
			}
			_ = c.Close()
			total++
		}
	}
}
