package dpi

import (
	"container/list"
	"sync"
	"time"
)

// DefaultHostnameCacheCapacity is how many distinct remote IPs
// HostnameCache remembers at once.
const DefaultHostnameCacheCapacity = 2048

// DefaultHostnameCacheTTL is how long a cached fallback hostname stays
// valid after its last update.
const DefaultHostnameCacheTTL = 10 * time.Minute

// hostnameCacheEntry is one HostnameCache row.
type hostnameCacheEntry struct {
	ip       string
	hostname string
	expires  time.Time
}

// HostnameCache is a per-IP fallback: it remembers the most recently
// observed hostname an Inspector found for a remote IP, for connections to
// the same IP that carry no hostname of their own. It is not authoritative —
// one IP can genuinely serve different hostnames on different connections
// (virtual hosting, CDNs) — so callers must always prefer a connection's own
// detected hostname over this cache, and consult it only as a fallback.
type HostnameCache struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	ll       *list.List
	index    map[string]*list.Element
}

// NewHostnameCache creates a HostnameCache bounded to capacity entries, each
// valid for ttl after its last update.
func NewHostnameCache(capacity int, ttl time.Duration) *HostnameCache {
	return &HostnameCache{
		capacity: capacity,
		ttl:      ttl,
		ll:       list.New(),
		index:    make(map[string]*list.Element, capacity),
	}
}

// Put records hostname as the latest observed value for ip. Last-seen-wins:
// this always overwrites whatever was cached before, even a different
// hostname, and refreshes both the TTL and the entry's recency.
func (c *HostnameCache) Put(ip, hostname string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.index[ip]; ok {
		c.ll.MoveToFront(el)
		e := el.Value.(*hostnameCacheEntry)
		e.hostname = hostname
		e.expires = now.Add(c.ttl)
		return
	}

	el := c.ll.PushFront(&hostnameCacheEntry{ip: ip, hostname: hostname, expires: now.Add(c.ttl)})
	c.index[ip] = el

	if c.ll.Len() > c.capacity {
		back := c.ll.Back()
		c.ll.Remove(back)
		delete(c.index, back.Value.(*hostnameCacheEntry).ip)
	}
}

// Get returns the fallback hostname for ip, if one is cached and
// unexpired. A hit promotes the entry to most-recently-used; an expired
// entry is evicted on read.
func (c *HostnameCache) Get(ip string, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.index[ip]
	if !ok {
		return "", false
	}

	e := el.Value.(*hostnameCacheEntry)
	if now.After(e.expires) {
		c.ll.Remove(el)
		delete(c.index, ip)
		return "", false
	}

	c.ll.MoveToFront(el)
	return e.hostname, true
}
