package dpi

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var epoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func TestHostnameCachePutGet(t *testing.T) {
	c := NewHostnameCache(10, time.Minute)
	c.Put("1.2.3.4", "example.com", epoch)

	got, ok := c.Get("1.2.3.4", epoch)
	if !ok || got != "example.com" {
		t.Fatalf("Get() = %q, %v; want %q, true", got, ok, "example.com")
	}

	if _, ok := c.Get("5.6.7.8", epoch); ok {
		t.Fatal("Get() for an IP never Put ok=true")
	}
}

func TestHostnameCacheExpiry(t *testing.T) {
	c := NewHostnameCache(10, time.Minute)
	c.Put("1.2.3.4", "example.com", epoch)

	if _, ok := c.Get("1.2.3.4", epoch.Add(time.Minute+time.Second)); ok {
		t.Fatal("Get() after TTL elapsed ok=true")
	}

	// The expired entry must actually be removed, not just reported miss:
	// re-check the internal bookkeeping via a fresh Put/Get round-trip.
	if got := c.ll.Len(); got != 0 {
		t.Fatalf("expired entry not evicted: list length = %d, want 0", got)
	}
}

func TestHostnameCacheLastSeenWins(t *testing.T) {
	c := NewHostnameCache(10, time.Minute)
	c.Put("1.2.3.4", "first.example.com", epoch)
	c.Put("1.2.3.4", "second.example.com", epoch.Add(time.Second))

	got, ok := c.Get("1.2.3.4", epoch.Add(time.Second))
	if !ok || got != "second.example.com" {
		t.Fatalf("Get() = %q, %v; want %q, true", got, ok, "second.example.com")
	}
}

func TestHostnameCacheLRUEviction(t *testing.T) {
	c := NewHostnameCache(2, time.Minute)
	c.Put("a", "a.example.com", epoch)
	c.Put("b", "b.example.com", epoch)

	// Promote "a" to most-recently-used before "c" forces an eviction.
	if _, ok := c.Get("a", epoch); !ok {
		t.Fatal("Get(a) = false before eviction")
	}
	c.Put("c", "c.example.com", epoch)

	if _, ok := c.Get("a", epoch); !ok {
		t.Fatal("Get(a) = false; \"a\" should have survived as recently-used")
	}
	if _, ok := c.Get("b", epoch); ok {
		t.Fatal("Get(b) = true; \"b\" should have been evicted as least-recently-used")
	}
	if _, ok := c.Get("c", epoch); !ok {
		t.Fatal("Get(c) = false; \"c\" was just inserted")
	}
}

// TestHostnameCacheConcurrentAccess exercises Put/Get from many goroutines at
// once, so `go test -race` can confirm the single mutex actually serializes
// every access to the cache's internal list and map.
func TestHostnameCacheConcurrentAccess(t *testing.T) {
	c := NewHostnameCache(64, time.Minute)

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", g)
			for i := range 100 {
				now := epoch.Add(time.Duration(i) * time.Millisecond)
				c.Put(ip, fmt.Sprintf("host-%d-%d.example.com", g, i), now)
				c.Get(ip, now)
			}
		}(g)
	}
	wg.Wait()
}
