package procinfo

import (
	"context"
	"sync"
	"time"
)

// PollInterval is how often the full PID/fd walk runs. Enumerating every
// process's descriptors is expensive, so this is deliberately slower than the
// packet capture loop.
const PollInterval = time.Second

// Process identifies the owner of a socket.
type Process struct {
	PID  int32
	Name string
}

// Poller periodically rebuilds the local-port to process mapping.
type Poller struct {
	mu    sync.RWMutex
	ports map[uint16]Process
	names map[int32]string // cache: PID to executable name
}

// NewPoller returns an idle Poller. Call Run to start polling.
func NewPoller() *Poller {
	return &Poller{
		ports: make(map[uint16]Process),
		names: make(map[int32]string),
	}
}

// Run polls until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) error {
	t := time.NewTicker(PollInterval)
	defer t.Stop()

	for {
		if err := p.poll(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// poll rebuilds the port map from scratch. Building fresh each time (rather
// than patching) is what makes port reuse safe: a recycled port always
// resolves to its current owner.
//
// The map is keyed on local port alone, which is what the capture side can
// cheaply key on too. Two processes can legitimately hold the same local port
// on different local addresses (a listener bound per-interface, or SO_REUSEPORT
// across a worker pool), in which case the last PID walked wins.
func (p *Poller) poll() error {
	pids, err := ListPIDs()
	if err != nil {
		return err
	}

	ports := make(map[uint16]Process, len(p.ports))

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, pid := range pids {
		socks, err := SocketsForPID(pid)
		if err != nil {
			// Processes come and go mid-walk, and some are simply not
			// inspectable. Skip rather than abandoning the whole poll.
			continue
		}
		if len(socks) == 0 {
			continue
		}

		name, ok := p.names[pid]
		if !ok {
			if name, err = ProcessName(pid); err != nil {
				name = "?"
			}
			p.names[pid] = name
		}

		for _, s := range socks {
			ports[s.LocalPort] = Process{PID: pid, Name: name}
		}
	}

	p.ports = ports
	return nil
}

// Lookup returns the process currently owning localPort.
func (p *Poller) Lookup(localPort uint16) (Process, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	proc, ok := p.ports[localPort]
	return proc, ok
}

// Snapshot returns a copy of the current port map for the aggregator to join
// against.
func (p *Poller) Snapshot() map[uint16]Process {
	p.mu.RLock()
	defer p.mu.RUnlock()

	out := make(map[uint16]Process, len(p.ports))
	for k, v := range p.ports {
		out[k] = v
	}
	return out
}
