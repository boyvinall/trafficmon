package capture

import (
	"testing"
	"time"
)

func TestByteCounterTotalsAreMonotonic(t *testing.T) {
	var c ByteCounter
	now := time.Now().Truncate(time.Second)

	c.Add(now, 100, true)
	c.Add(now.Add(time.Second), 50, false)
	// Well beyond the rate window: totals must survive, rates must not.
	c.Add(now.Add(time.Minute), 25, true)

	in, out := c.Totals()
	if in != 125 || out != 50 {
		t.Fatalf("totals = (%d, %d), want (125, 50)", in, out)
	}
}

func TestByteCounterRateOverWindow(t *testing.T) {
	var c ByteCounter
	now := time.Now().Truncate(time.Second)

	// One second's worth of traffic, read back within the window.
	c.Add(now, 5000, true)
	c.Add(now, 1000, false)

	in, out := c.Rates(now)
	wantIn := 5000.0 / rateWindow.Seconds()
	wantOut := 1000.0 / rateWindow.Seconds()
	if in != wantIn || out != wantOut {
		t.Fatalf("rates = (%.1f, %.1f), want (%.1f, %.1f)", in, out, wantIn, wantOut)
	}
}

func TestByteCounterRateDecaysToZero(t *testing.T) {
	var c ByteCounter
	now := time.Now().Truncate(time.Second)

	c.Add(now, 5000, true)

	// Once the whole window has rolled past, a silent flow reads as zero
	// rather than holding its last rate.
	in, out := c.Rates(now.Add(rateWindow + time.Second))
	if in != 0 || out != 0 {
		t.Fatalf("rates after idle = (%.1f, %.1f), want (0, 0)", in, out)
	}
}

func TestByteCounterRingWrapsWithoutLosingRecentTraffic(t *testing.T) {
	var c ByteCounter
	now := time.Now().Truncate(time.Second)

	// Traffic every second for longer than the ring: only the last
	// rateBuckets seconds should count towards the rate.
	for i := range 20 {
		c.Add(now.Add(time.Duration(i)*time.Second), 1000, true)
	}

	in, _ := c.Rates(now.Add(19 * time.Second))
	want := float64(rateBuckets*1000) / rateWindow.Seconds()
	if in != want {
		t.Fatalf("rate = %.1f, want %.1f", in, want)
	}

	if total, _ := c.Totals(); total != 20000 {
		t.Fatalf("total = %d, want 20000", total)
	}
}

func TestRateWindowMatchesBucketCount(t *testing.T) {
	// The rate maths divides the whole ring by rateWindow, so the two
	// constants must stay in step.
	if time.Duration(rateBuckets)*time.Second != rateWindow {
		t.Fatalf("rateBuckets (%d) does not cover rateWindow (%s)", rateBuckets, rateWindow)
	}
}
