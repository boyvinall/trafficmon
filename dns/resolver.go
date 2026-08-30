// Package dns provides asynchronous reverse DNS lookups with a cache. Lookups
// never block the render loop: callers get the bare IP until a name resolves.
package dns

import (
	"context"
	"sync"
)

// Resolver caches reverse lookups and resolves misses in the background.
type Resolver struct {
	mu       sync.RWMutex
	cache    map[string]string // IP to hostname; empty value means "does not resolve"
	inflight map[string]struct{}
}

// NewResolver returns an empty resolver.
func NewResolver() *Resolver {
	return &Resolver{
		cache:    make(map[string]string),
		inflight: make(map[string]struct{}),
	}
}

// Lookup returns the cached hostname for ip if one is known, and otherwise
// returns ip immediately while kicking off a background resolve. A negative
// result is cached permanently: failures are never retried.
//
// TODO(milestone 7): spawn the background net.LookupAddr and fill the cache.
func (r *Resolver) Lookup(ctx context.Context, ip string) string {
	r.mu.RLock()
	name, ok := r.cache[ip]
	r.mu.RUnlock()

	if ok && name != "" {
		return name
	}
	if ok {
		return ip
	}

	_ = ctx
	return ip
}
