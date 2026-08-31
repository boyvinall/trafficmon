package dns

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// testIP is the address most of these tests ask about; nothing about it
// matters except that it is not the empty string.
const testIP = "140.82.112.3"

// errNoSuchHost stands in for whatever the stub resolver would have returned
// for an address with no PTR record.
var errNoSuchHost = errors.New("no such host")

// waitFor polls cond until it holds, failing the test if it never does.
//
// The whole point of the resolver is that the answer arrives on some other
// goroutine at some later moment, so the tests over it cannot avoid waiting.
// Polling rather than sleeping a fixed interval keeps them fast — they end the
// instant the work lands — and keeps the deadline long enough that only a
// genuine failure ever reaches it.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// resolvesTo is a lookup function that answers from a fixed name, counting how
// many times it was called. The trailing dot is the one the real resolver
// returns, so that stripping it is exercised rather than assumed.
func resolvesTo(name string, calls *atomic.Int64) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) {
		calls.Add(1)
		return []string{name + "."}, nil
	}
}

func TestLookupReturnsTheAddressUntilItResolves(t *testing.T) {
	var calls atomic.Int64
	r := NewResolverWith(resolvesTo("lb.github.com", &calls))

	// The first ask can only ever return the address: the query has not been
	// made yet, and the render loop is not going to be held up while it is.
	if got := r.Lookup(context.Background(), testIP); got != testIP {
		t.Fatalf("first Lookup = %q, want the bare address %q", got, testIP)
	}

	waitFor(t, "the name to reach the cache", func() bool {
		return r.Lookup(context.Background(), testIP) == "lb.github.com"
	})
}

func TestLookupStartsOneQueryPerAddress(t *testing.T) {
	var calls atomic.Int64
	release := make(chan struct{})
	r := NewResolverWith(func(ctx context.Context, addr string) ([]string, error) {
		calls.Add(1)
		<-release
		return resolvesTo("lb.github.com", &atomic.Int64{})(ctx, addr)
	})

	r.Lookup(context.Background(), testIP)
	waitFor(t, "the query to start", func() bool { return calls.Load() == 1 })

	// A table redrawing once a second asks about every address on screen every
	// second, for as long as it takes the answer to arrive. Without the
	// inflight guard that is one query per frame per address.
	for range 100 {
		if got := r.Lookup(context.Background(), testIP); got != testIP {
			t.Fatalf("Lookup = %q while the query is still in flight, want %q", got, testIP)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("%d queries started for one address, want 1", got)
	}

	close(release)
	waitFor(t, "the name to reach the cache", func() bool {
		return r.Lookup(context.Background(), testIP) == "lb.github.com"
	})

	// And a resolved address is answered from the cache rather than asked
	// about again.
	for range 100 {
		r.Lookup(context.Background(), testIP)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("%d queries in total, want 1", got)
	}
}

func TestLookupCachesFailuresAndNeverRetriesThem(t *testing.T) {
	var calls atomic.Int64
	r := NewResolverWith(func(context.Context, string) ([]string, error) {
		calls.Add(1)
		return nil, errNoSuchHost
	})

	r.Lookup(context.Background(), testIP)
	waitFor(t, "the failure to be recorded", func() bool { return calls.Load() == 1 })
	waitFor(t, "the query to finish", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.inflight) == 0
	})

	// The plan is explicit that an address which does not resolve falls back
	// to the bare IP permanently rather than being retried every tick, so an
	// hour of frames must cost exactly the one query it already made.
	for range 100 {
		if got := r.Lookup(context.Background(), testIP); got != testIP {
			t.Fatalf("Lookup = %q after a failure, want the bare address %q", got, testIP)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("%d queries for an address that does not resolve, want 1", got)
	}
}

func TestLookupCachesAnEmptyAnswerAsAFailure(t *testing.T) {
	var calls atomic.Int64
	r := NewResolverWith(func(context.Context, string) ([]string, error) {
		calls.Add(1)
		return nil, nil
	})

	// A resolver that succeeds with no names has still not named the address,
	// and there is nothing to gain by asking it again.
	r.Lookup(context.Background(), testIP)
	waitFor(t, "the empty answer to be recorded", func() bool { return calls.Load() == 1 })
	waitFor(t, "the query to finish", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.inflight) == 0
	})

	for range 100 {
		if got := r.Lookup(context.Background(), testIP); got != testIP {
			t.Fatalf("Lookup = %q, want the bare address %q", got, testIP)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("%d queries after an empty answer, want 1", got)
	}
}

func TestLookupDoesNotBlockOnASlowQuery(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	r := NewResolverWith(func(ctx context.Context, _ string) ([]string, error) {
		<-release
		return nil, ctx.Err()
	})

	// Every one of these is a query that will not answer until the test lets
	// it. If Lookup waited on any of them the render loop would stall for the
	// whole timeout, and this test would hang rather than fail.
	start := time.Now()
	for i := range 100 {
		ip := fmt.Sprintf("10.0.0.%d", i)
		if got := r.Lookup(context.Background(), ip); got != ip {
			t.Fatalf("Lookup(%q) = %q, want the bare address", ip, got)
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("100 lookups against a stalled resolver took %v; Lookup is blocking", elapsed)
	}
}

func TestLookupCapsConcurrentQueries(t *testing.T) {
	var live, peak atomic.Int64
	release := make(chan struct{})
	defer close(release)

	r := NewResolverWith(func(context.Context, string) ([]string, error) {
		n := live.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		live.Add(-1)
		return nil, errNoSuchHost
	})

	// A screenful of a busy machine, against a resolver that never answers:
	// far more distinct addresses than there are slots, asked about on every
	// frame the way the render loop would.
	waitFor(t, "the slots to fill", func() bool {
		for i := range 200 {
			r.Lookup(context.Background(), fmt.Sprintf("10.0.%d.%d", i/256, i%256))
		}
		return peak.Load() == maxConcurrent
	})

	if got := peak.Load(); got > maxConcurrent {
		t.Errorf("%d queries ran at once, want at most %d", got, maxConcurrent)
	}
}

func TestLookupAbandonsACancelledQueryWithoutCachingIt(t *testing.T) {
	var calls atomic.Int64
	blocked := make(chan struct{}, 1)
	r := NewResolverWith(func(ctx context.Context, _ string) ([]string, error) {
		// Only the first query waits to be cancelled; the retry the test is
		// really about answers straight away.
		if calls.Add(1) == 1 {
			blocked <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return []string{"lb.github.com."}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	r.Lookup(ctx, testIP)
	<-blocked
	cancel()

	waitFor(t, "the cancelled query to be abandoned", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.inflight) == 0
	})

	// A cancelled parent says nothing about whether the address resolves, so
	// it must not have been written off as one that never will.
	waitFor(t, "the address to resolve on a second attempt", func() bool {
		return r.Lookup(context.Background(), testIP) == "lb.github.com"
	})
}

func TestLookupGivesUpOnAQueryThatNeverAnswers(t *testing.T) {
	var calls atomic.Int64
	r := NewResolverWith(func(ctx context.Context, _ string) ([]string, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	})

	// The real timeout is seconds long, which is right for a black-holed
	// server and wrong for a test; the behaviour under test is what happens
	// when it expires, not how long that takes.
	r.timeout = 10 * time.Millisecond

	r.Lookup(context.Background(), testIP)
	waitFor(t, "the query to time out", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.inflight) == 0
	})

	// A server that will not answer is as permanent a failure as an address
	// with no record: retrying it every tick would spend a slot a second on
	// something that has already cost two seconds of waiting.
	for range 100 {
		if got := r.Lookup(context.Background(), testIP); got != testIP {
			t.Fatalf("Lookup = %q after a timeout, want the bare address %q", got, testIP)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("%d queries after a timeout, want 1", got)
	}
}

func TestLookupIgnoresTheEmptyAddress(t *testing.T) {
	var calls atomic.Int64
	r := NewResolverWith(resolvesTo("lb.github.com", &calls))

	// By-process rows carry no destination. Resolving them uniformly is the
	// caller's simplest option, so the empty string has to be cheap and inert
	// rather than a query for the PTR record of nothing.
	if got := r.Lookup(context.Background(), ""); got != "" {
		t.Errorf("Lookup(\"\") = %q, want \"\"", got)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("%d queries for the empty address, want 0", got)
	}
}

func TestCacheIsBoundedAndKeepsWhatIsStillAskedAbout(t *testing.T) {
	r := NewResolverWith(func(context.Context, string) ([]string, error) {
		return nil, errNoSuchHost
	})

	const hot = "140.82.112.3"

	r.mu.Lock()
	defer r.mu.Unlock()

	r.put(hot, result{name: "lb.github.com", resolved: true})

	// Several generations' worth of addresses seen once and never again,
	// which is what a long session on a busy machine actually produces.
	for i := range maxCacheEntries * 3 {
		r.put(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff), result{})

		// One address stays on screen throughout, so it is asked about on
		// every frame the way a live destination would be.
		r.get(hot)
	}

	if total := len(r.cur) + len(r.prev); total > 2*maxCacheEntries {
		t.Errorf("cache holds %d entries after %d addresses, want at most %d",
			total, maxCacheEntries*3, 2*maxCacheEntries)
	}

	res, ok := r.get(hot)
	if !ok || res.name != "lb.github.com" {
		t.Errorf("the address still on screen was evicted: got %+v, cached %t", res, ok)
	}
}

func TestWithLookupTimeoutOverridesTheDefault(t *testing.T) {
	var calls atomic.Int64
	r := NewResolverWith(func(ctx context.Context, _ string) ([]string, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}, WithLookupTimeout(10*time.Millisecond))

	if r.timeout != 10*time.Millisecond {
		t.Fatalf("timeout = %v, want the overridden 10ms", r.timeout)
	}

	// The override has to actually reach the query, not just the field: a
	// query that outlives it must still be cut off promptly rather than
	// running out to the package default of two seconds.
	start := time.Now()
	r.Lookup(context.Background(), testIP)
	waitFor(t, "the query to time out", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.inflight) == 0
	})
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("query timed out after %v, want it bounded by the overridden 10ms", elapsed)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("%d queries, want 1", got)
	}
}

func TestWithMaxConcurrentOverridesTheDefault(t *testing.T) {
	var live, peak atomic.Int64
	release := make(chan struct{})
	defer close(release)

	const limit = 2
	r := NewResolverWith(func(context.Context, string) ([]string, error) {
		n := live.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		live.Add(-1)
		return nil, errNoSuchHost
	}, WithMaxConcurrent(limit))

	waitFor(t, "the slots to fill", func() bool {
		for i := range 20 {
			r.Lookup(context.Background(), fmt.Sprintf("10.0.%d.%d", i/256, i%256))
		}
		return peak.Load() == limit
	})

	if got := peak.Load(); got > limit {
		t.Errorf("%d queries ran at once, want at most the overridden %d", got, limit)
	}
}

func TestWithMaxCacheEntriesOverridesTheDefault(t *testing.T) {
	r := NewResolverWith(func(context.Context, string) ([]string, error) {
		return nil, errNoSuchHost
	}, WithMaxCacheEntries(2))

	r.mu.Lock()
	defer r.mu.Unlock()

	r.put("10.0.0.1", result{})
	r.put("10.0.0.2", result{})
	if len(r.cur) != 2 {
		t.Fatalf("cur holds %d entries before the generation is full, want 2", len(r.cur))
	}

	// A third entry has to roll the generation over at the overridden size of
	// two, not at the package default of 4096.
	r.put("10.0.0.3", result{})
	if len(r.cur) != 1 || len(r.prev) != 2 {
		t.Errorf("after rollover cur=%d prev=%d, want cur=1 prev=2", len(r.cur), len(r.prev))
	}
}

func TestFirstName(t *testing.T) {
	tests := []struct {
		name  string
		names []string
		want  string
	}{
		{
			// The trailing dot is correct and reads as a typo in a table.
			name:  "fully qualified name is trimmed",
			names: []string{"lb.github.com."},
			want:  "lb.github.com",
		},
		{
			name:  "several records take the first",
			names: []string{"one.example.com.", "two.example.com."},
			want:  "one.example.com",
		},
		{
			name:  "no records",
			names: nil,
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstName(tc.names); got != tc.want {
				t.Errorf("firstName(%v) = %q, want %q", tc.names, got, tc.want)
			}
		})
	}
}
