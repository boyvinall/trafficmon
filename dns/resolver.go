// Package dns provides asynchronous reverse DNS lookups with a cache. Lookups
// never block the render loop: callers get the bare IP until a name resolves.
package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// lookupTimeout bounds a single reverse query.
	//
	// It is deliberately much shorter than a stub resolver's own retry
	// schedule, which can run to tens of seconds: a name that takes that long
	// to arrive is worth nothing to a table that has already been redrawn with
	// the bare IP a dozen times over, and the slot it holds is better spent on
	// an address that will answer.
	lookupTimeout = 2 * time.Second

	// maxConcurrent caps the queries in flight, and with them the goroutines.
	//
	// A single busy screenful can carry hundreds of distinct addresses. Firing
	// a resolve at every one of them at once would swamp the stub resolver,
	// and against a black-holed server it would leave hundreds of goroutines
	// parked for the whole timeout. An address that cannot get a slot is
	// simply not looked up: the next tick offers it again a second later, so
	// the backlog drains without ever being materialised as a queue.
	maxConcurrent = 8

	// maxCacheEntries is how many addresses one generation of the cache holds
	// before it is rotated out. See put for why that bounds the whole thing at
	// twice this number.
	maxCacheEntries = 4096
)

// result is a completed lookup.
//
// Whether the address resolved is carried separately from the name rather than
// an empty name standing in for failure, because "resolved to nothing" and
// "never will resolve" are not the same promise to the caller, and because
// there is a third state — no answer yet — that has to stay distinct from
// both. That third state lives in the inflight set rather than the cache,
// which is what stops a query still in progress from being read as a failure.
type result struct {
	name     string
	resolved bool
}

// Resolver caches reverse lookups and resolves misses in the background.
//
// The zero value is not usable; call NewResolver.
type Resolver struct {
	// mu is a plain Mutex rather than an RWMutex because a cache *hit* may
	// write: finding an address in the outgoing generation promotes it into
	// the current one. The critical sections are map operations on a cache
	// read once per row per second, so there is nothing here for a reader
	// lock to win back.
	mu sync.Mutex

	// cur and prev are two generations of one cache. Everything lands in cur;
	// prev is the previous generation, still serving lookups but no longer
	// accepting new ones.
	cur, prev map[string]result

	// inflight holds the addresses a background query has already been
	// started for, so that a busy table redrawing every second launches one
	// lookup per address rather than one per frame.
	inflight map[string]struct{}

	// sem hands out the concurrent lookup slots. It is acquired without
	// blocking, so a full semaphore skips the lookup rather than queueing it.
	sem chan struct{}

	// lookup performs the reverse query and timeout bounds it. Both are
	// fields rather than direct uses of net.DefaultResolver so that tests can
	// drive failures, slow answers and successes deterministically, without
	// making a real DNS query.
	lookup  func(ctx context.Context, addr string) ([]string, error)
	timeout time.Duration

	// maxConcurrent and maxCacheEntries mirror the package constants of the
	// same name, defaulted from them in NewResolverWith and overridable via
	// Option. They are plain fields rather than the constants directly so
	// that an Option can change them per Resolver.
	maxConcurrent   int
	maxCacheEntries int
}

// Option overrides one of a Resolver's tunables from its default. See
// WithLookupTimeout, WithMaxConcurrent and WithMaxCacheEntries.
type Option func(*Resolver)

// WithLookupTimeout overrides lookupTimeout, the bound on a single reverse
// query.
func WithLookupTimeout(d time.Duration) Option {
	return func(r *Resolver) { r.timeout = d }
}

// WithMaxConcurrent overrides maxConcurrent, the number of reverse queries
// allowed in flight at once. n below 1 is treated as 1, since 0 would
// silently disable all lookups and a negative n would panic the buffered
// channel NewResolverWith allocates from it.
func WithMaxConcurrent(n int) Option {
	return func(r *Resolver) { r.maxConcurrent = max(n, 1) }
}

// WithMaxCacheEntries overrides maxCacheEntries, the size of one generation
// of the cache. See put for why that bounds the whole thing at twice this
// number. n below 1 is treated as 1, since put rotates generations on every
// write once maxCacheEntries is non-positive.
func WithMaxCacheEntries(n int) Option {
	return func(r *Resolver) { r.maxCacheEntries = max(n, 1) }
}

// NewResolver returns an empty resolver that asks the system resolver.
func NewResolver(opts ...Option) *Resolver {
	return NewResolverWith(net.DefaultResolver.LookupAddr, opts...)
}

// NewResolverWith returns an empty resolver that runs its queries through
// lookup rather than the system resolver.
//
// It is the seam the tests are written against: reverse lookups that fail,
// that answer slowly, or that answer at all are all properties of the network
// the suite happens to run on, so a test that used the real resolver would be
// testing the network. It is exported because the callers that have to be
// tested this way — the render loop among them — live in other packages.
//
// opts override the package defaults for lookup timeout, concurrency and
// cache size; callers that pass none get the current constants.
func NewResolverWith(lookup func(ctx context.Context, addr string) ([]string, error), opts ...Option) *Resolver {
	r := &Resolver{
		cur:             make(map[string]result),
		prev:            make(map[string]result),
		inflight:        make(map[string]struct{}),
		lookup:          lookup,
		timeout:         lookupTimeout,
		maxConcurrent:   maxConcurrent,
		maxCacheEntries: maxCacheEntries,
	}
	for _, opt := range opts {
		opt(r)
	}
	r.sem = make(chan struct{}, r.maxConcurrent)
	return r
}

// Lookup returns the cached hostname for ip if one is known, and otherwise
// returns ip immediately while starting a background resolve. It never blocks:
// a caller may hold the render loop while calling it.
//
// A negative result is cached permanently, so an address that does not resolve
// is asked about once and then shows as a bare IP for the rest of the session
// rather than being retried on every tick. ctx is the parent of the background
// query: cancelling it abandons the lookup without recording that failure,
// since a program shutting down says nothing about whether the name exists.
//
// Only the ctx passed by whichever call actually starts the background query
// bounds it: while that query is in flight, every later Lookup for the same
// ip returns immediately without even looking at the ctx it was given. A
// caller relying on its own ctx to bound every call it makes, rather than
// just the first, should not assume cancelling one call's ctx affects a
// lookup another call already started.
func (r *Resolver) Lookup(ctx context.Context, ip string) string {
	// ByProcess rows carry no destination, so a caller that resolves every row
	// uniformly hands the empty string over rather than having to know which
	// view it is in.
	if ip == "" {
		return ip
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if res, ok := r.get(ip); ok {
		if res.resolved {
			return res.name
		}
		return ip
	}
	if _, busy := r.inflight[ip]; busy {
		return ip
	}

	// The slot is taken here, under the lock, rather than inside the
	// goroutine: a select with a default never blocks, and taking it before
	// spawning is what makes maxConcurrent a bound on goroutines and not just
	// on queries. Missing out costs nothing — the address is left unmarked, so
	// the next tick tries again.
	select {
	case r.sem <- struct{}{}:
	default:
		return ip
	}

	r.inflight[ip] = struct{}{}
	go r.resolve(ctx, ip)
	return ip
}

// resolve performs one background query and records what it found.
//
// It runs r.lookup on its own goroutine rather than inline, and releases its
// semaphore slot the instant queryCtx expires rather than waiting on that
// goroutine — lookup is r.timeout's only enforcer for a real net.Resolver,
// but not every platform resolver actually honors a context deadline for a
// reverse (PTR) query, and a lookup call that outlives its deadline must not
// pin a slot forever: with maxConcurrent capped low, enough stuck queries
// would wedge every future lookup. The stray goroutine is simply abandoned to
// finish or never finish on its own; its answer, if it ever arrives, is
// discarded rather than recorded, since by then a fresher attempt may already
// own the address.
func (r *Resolver) resolve(ctx context.Context, ip string) {
	defer func() { <-r.sem }()

	queryCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	type answer struct {
		names []string
		err   error
	}
	done := make(chan answer, 1)
	go func() {
		names, err := r.lookup(queryCtx, ip)
		done <- answer{names: names, err: err}
	}()

	var names []string
	var err error
	select {
	case a := <-done:
		names, err = a.names, a.err
	case <-queryCtx.Done():
		err = queryCtx.Err()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Clearing the mark unconditionally is what keeps a cancelled or dropped
	// lookup from wedging an address as permanently "in progress" and so never
	// asked about again.
	delete(r.inflight, ip)

	// A cancelled parent is the program winding up, not an answer about this
	// address. Caching a negative for it would be a permanent decision taken
	// on no evidence — and one that outlives the cancellation if the resolver
	// is shared — so the address is simply left unknown.
	if ctx.Err() != nil {
		return
	}

	name := firstName(names)
	r.put(ip, result{name: name, resolved: err == nil && name != ""})
}

// get reads an address out of either generation, promoting a hit in the
// outgoing one so that an address still being talked to survives the next
// rotation. The caller must hold mu.
func (r *Resolver) get(ip string) (result, bool) {
	if res, ok := r.cur[ip]; ok {
		return res, true
	}
	res, ok := r.prev[ip]
	if ok {
		r.put(ip, res)
	}
	return res, ok
}

// put records a completed lookup, rotating the generations when the current
// one is full. The caller must hold mu.
//
// Rotating wholesale is why there is no eviction list to maintain: the
// outgoing generation keeps answering while the new one fills, so anything
// still on screen is promoted back on its next lookup and only genuinely cold
// addresses are lost. Memory is bounded at twice maxCacheEntries, which for a
// session lasting hours is what stops a machine talking to a lot of hosts from
// growing the cache without limit. The bound is deliberately generous: the
// aggregator evicts a flow seconds after it goes quiet, but a name is worth
// keeping long after that, since the same host is usually talked to again.
func (r *Resolver) put(ip string, res result) {
	if len(r.cur) >= r.maxCacheEntries {
		r.prev, r.cur = r.cur, make(map[string]result, r.maxCacheEntries)
	}
	r.cur[ip] = res
}

// firstName picks the hostname to display from a reverse lookup's answers.
//
// An address may have several PTR records and the order they arrive in is not
// meaningful, so the first is as good a choice as any and is what every other
// tool shows. The trailing dot of the fully qualified name is stripped: it is
// correct but it reads as a typo in a table.
func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
