// Package capture runs a live pcap handle, decoding packets into per-flow
// byte counters and dispatching candidate packets to DPI inspectors.
package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sync/errgroup"

	"github.com/boyvinall/trafficmon/capture/pcapdrv"
	"github.com/boyvinall/trafficmon/dpi"
)

// bpfFilter keeps the kernel from handing us anything the decoder cannot use:
// TCP/UDP (attributable to a socket), plus ICMP and ARP, which are shown with
// no process attribution since neither has one.
const bpfFilter = "tcp or udp or icmp or icmp6 or arp"

// minPayloadDatagramLen is a header-only TCP segment's (SYN, bare ACK, FIN)
// upper bound even with a full set of TCP options -- anything at or below
// it carries no application-layer bytes worth extracting for any Inspector,
// so inspect uses it to skip extraction entirely rather than ask a content
// check to reject an empty payload.
const minPayloadDatagramLen = 120

// statsSampleInterval bounds how often captureOn samples pcap.Handle.Stats()
// per interface — cheap, but no reason to call it on every packet when the
// read loop already wakes at least this often via readTimeout.
const statsSampleInterval = time.Second

// readTimeout bounds how long one read blocks inside libpcap.
//
// pcap.BlockForever would park the reader in libpcap while holding the
// handle's mutex, so a Close from another goroutine could not interrupt it and
// a quiet interface would keep Run alive long past ctx being cancelled. A
// short timeout lets the loop come up for air and check ctx instead.
const readTimeout = 250 * time.Millisecond

// Config controls live packet capture.
type Config struct {
	// Interface to capture on. Empty means auto-detect from the default route.
	Interface string

	// IncludeLoopback captures lo0 traffic as well as the primary interface.
	IncludeLoopback bool

	// SnapLen is the per-packet capture length. It has to cover more than
	// headers now that DPI inspects payload bytes: 1600 covers any TLS
	// ClientHello that fits in a single packet, since that is itself bounded
	// by the ~1500-byte link MTU almost everywhere, with margin for the
	// Ethernet/VLAN header. A ClientHello fragmented across multiple TCP
	// segments (large post-quantum key_share/ECH configs can do this) is
	// reassembled by Capturer.inspect within dpi.HelloAssembler's bounds — a
	// contiguous, in-order run of segments up to a fixed size and count. A
	// stream that arrives reordered, retransmitted, or with a gap still goes
	// undetected: that needs full TCP reassembly, which stays out of scope.
	SnapLen int

	// Inspectors are the DPI routines run against each flow's early packets
	// to identify that flow's own hostname. Nil or empty disables DPI
	// entirely.
	Inspectors []dpi.Inspector

	// PassiveInspectors are the DPI routines run against every packet to
	// learn hostnames for endpoints other than the one the packet arrived
	// on — DNS answers being the obvious source — fed straight into
	// HostnameCache. Nil or empty disables passive DPI entirely.
	PassiveInspectors []dpi.PassiveInspector

	// EnableLogFeed allocates the streaming SYN/DNS-query log feed (see
	// LogFeed) alongside the existing drop-oldest ring buffers. Left false
	// by default so the feed costs nothing — not even an unread channel —
	// when nothing is consuming it.
	EnableLogFeed bool
}

// DefaultConfig returns the capture defaults.
func DefaultConfig() Config {
	return Config{
		SnapLen:           1600,
		Inspectors:        dpi.DefaultInspectors(),
		PassiveInspectors: dpi.DefaultPassiveInspectors(),
	}
}

// Capturer owns the pcap handle and the flow table it feeds.
type Capturer struct {
	cfg Config

	mu    sync.RWMutex
	flows map[FlowKey]*ByteCounter

	// hostnameCache is the per-IP fallback: a flow with no hostname of its own
	// can borrow the most recent one DPI found for the same remote IP.
	hostnameCache *dpi.HostnameCache

	// dnsQueries holds DNS query findings until the next DrainDNSQueries —
	// unlike hostnameCache, these are never authoritative hostname data, so
	// they get their own bounded buffer instead.
	dnsQueries *dnsQueryRing

	// synEvents holds SYN-only packets (connection attempts) until the next
	// DrainSYNEvents.
	synEvents *synEventRing

	// rstEvents holds RST packets until the next DrainRSTEvents.
	rstEvents *rstEventRing

	// dnsErrors holds DNS error findings until the next DrainDNSErrors.
	dnsErrors *dnsErrorRing

	// logFeed streams SYN/DNS-query events to a consumer in real time,
	// nil unless cfg.EnableLogFeed is set — see logFeed's doc comment.
	logFeed *logFeed

	statsMu sync.Mutex
	// packetStats holds each interface's most recently sampled pcap.Handle
	// statistics, keyed by interface name.
	packetStats map[string]PacketStats
}

// New creates a Capturer. It does not open the interface; call Run for that.
func New(cfg Config) *Capturer {
	c := &Capturer{
		cfg:           cfg,
		flows:         make(map[FlowKey]*ByteCounter),
		hostnameCache: dpi.NewHostnameCache(dpi.DefaultHostnameCacheCapacity, dpi.DefaultHostnameCacheTTL),
		dnsQueries:    newDNSQueryRing(),
		synEvents:     newSYNEventRing(),
		rstEvents:     newRSTEventRing(),
		dnsErrors:     newDNSErrorRing(),
		packetStats:   make(map[string]PacketStats),
	}
	if cfg.EnableLogFeed {
		c.logFeed = newLogFeed()
	}
	return c
}

// PacketStats returns a copy of each interface's most recently sampled pcap
// statistics, keyed by interface name.
func (c *Capturer) PacketStats() map[string]PacketStats {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()

	out := make(map[string]PacketStats, len(c.packetStats))
	for k, v := range c.packetStats {
		out[k] = v
	}
	return out
}

// HostnameCache returns the per-IP hostname fallback cache DPI populates, for the
// UI to consult when a connection has no hostname of its own.
func (c *Capturer) HostnameCache() *dpi.HostnameCache {
	return c.hostnameCache
}

// DrainDNSQueries returns every DNS query finding captured since the last
// call and resets the buffer to empty.
func (c *Capturer) DrainDNSQueries() []dpi.QueryFinding {
	return c.dnsQueries.drain()
}

// DrainSYNEvents returns every SYN-only packet (connection attempt) captured
// since the last call and resets the buffer to empty.
func (c *Capturer) DrainSYNEvents() []SYNEvent {
	return c.synEvents.drain()
}

// DrainRSTEvents returns every RST packet captured since the last call and
// resets the buffer to empty.
func (c *Capturer) DrainRSTEvents() []RSTEvent {
	return c.rstEvents.drain()
}

// DrainDNSErrors returns every DNS error finding captured since the last call
// and resets the buffer to empty.
func (c *Capturer) DrainDNSErrors() []dpi.DNSErrorFinding {
	return c.dnsErrors.drain()
}

// LogFeed returns the streaming SYN/DNS-query channels a logs consumer can
// read from directly, as an alternative to the slower Drain*-based ring
// buffers. ok is false when cfg.EnableLogFeed wasn't set, distinguishing
// "disabled" from "enabled but currently empty".
func (c *Capturer) LogFeed() (syn <-chan SYNEvent, dnsQuery <-chan dpi.QueryFinding, ok bool) {
	if c.logFeed == nil {
		return nil, nil, false
	}
	return c.logFeed.syn, c.logFeed.dnsQuery, true
}

// LogFeedOverflow passes through the log feed's cumulative drop counts, or
func (c *Capturer) LogFeedOverflow() (syn, dnsQuery uint64) {
	if c.logFeed == nil {
		return 0, 0
	}
	return c.logFeed.overflow()
}

// Run opens the interface and decodes packets into the flow table. If ctx is
// cancelled or its deadline expires, Run returns ctx.Err(); it can also
// return earlier than that with a different error — an invalid SnapLen, a
// failure to open the interface or set the BPF filter, an unsupported link
// type, or a read error (including the handle reaching EOF) all cause it to
// return before ctx is done.
func (c *Capturer) Run(ctx context.Context) error {
	if c.cfg.SnapLen < 1 || c.cfg.SnapLen > math.MaxInt32 {
		return fmt.Errorf("SnapLen %d out of range [1, %d]", c.cfg.SnapLen, math.MaxInt32)
	}

	iface := c.cfg.Interface
	if iface == "" {
		var err error
		if iface, err = DefaultInterface(); err != nil { //nolint:contextcheck // DefaultInterface deliberately owns its own short, fixed timeout rather than ctx's
			return fmt.Errorf("detect interface: %w", err)
		}
	}

	ifaces := []string{iface}
	if c.cfg.IncludeLoopback && iface != loopbackInterface {
		// Loopback traffic never reaches the primary interface, so it needs a
		// handle of its own feeding the same flow map.
		ifaces = append(ifaces, loopbackInterface)
	}

	locals, err := localAddrSet(ifaces)
	if err != nil {
		return err
	}
	isLocal := func(a netip.Addr) bool {
		_, found := locals[a]
		return found
	}

	g, ctx := errgroup.WithContext(ctx)
	for _, iface := range ifaces {
		g.Go(func() error { return c.captureOn(ctx, iface, isLocal) })
	}
	return g.Wait()
}

// captureOn drives one pcap handle. It owns that handle for its whole life, so
// nothing else can close it out from under the read in progress.
func (c *Capturer) captureOn(ctx context.Context, iface string, isLocal func(netip.Addr) bool) error {
	// Promiscuous mode stays off: we only want traffic this host is an
	// endpoint of, and anything else would be attributed to no local socket.
	handle, err := pcapdrv.OpenLive(iface, int32(c.cfg.SnapLen), false, readTimeout)
	if err != nil {
		return fmt.Errorf("open %s: %w", iface, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return fmt.Errorf("set filter on %s: %w", iface, err)
	}

	dec, err := newFlowDecoder(handle.LinkType())
	if err != nil {
		return fmt.Errorf("decode %s: %w", iface, err)
	}

	var lastStatsUpdate time.Time

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if shouldSampleStats(lastStatsUpdate, time.Now(), statsSampleInterval) {
			lastStatsUpdate = time.Now()
			if stats, err := handle.Stats(); err == nil {
				c.statsMu.Lock()
				c.packetStats[iface] = PacketStats{
					Received:  stats.PacketsReceived,
					Dropped:   stats.PacketsDropped,
					IfDropped: stats.PacketsIfDropped,
				}
				c.statsMu.Unlock()
			}
		}

		// Zero-copy is safe here because everything kept from the packet —
		// addresses, ports, lengths — is copied into values before the next
		// read invalidates the buffer.
		data, ci, err := handle.ZeroCopyReadPacketData()
		switch {
		case err == nil:
		case errors.Is(err, pcapdrv.ErrTimeoutExpired):
			continue
		case errors.Is(err, io.EOF):
			return fmt.Errorf("capture on %s ended", iface)
		default:
			return fmt.Errorf("read from %s: %w", iface, err)
		}

		info, ok := dec.decode(data)
		if !ok {
			continue
		}
		key, inbound, ok := normalise(info.Src, info.Dst, info.SrcPort, info.DstPort, info.Proto, iface, isLocal)
		if !ok {
			continue
		}

		// libpcap timestamps come from the kernel at capture time, which is
		// closer to when the bytes moved than any clock read here would be.
		ts := ci.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		ctr := c.record(key, ts, info.Bytes, inbound)
		c.inspect(data, info, inbound, dec.linkType, key.RemoteAddr, ctr, ts)
		c.inspectPassive(data, info, dec.linkType, ts)

		if info.Proto == ProtoTCP && info.SYN && !info.ACK {
			ev := SYNEvent{
				Iface:      iface,
				LocalAddr:  key.LocalAddr,
				LocalPort:  key.LocalPort,
				RemoteAddr: key.RemoteAddr,
				RemotePort: key.RemotePort,
				At:         ts,
			}
			c.synEvents.push(ev)
			if c.logFeed != nil {
				c.logFeed.sendSYN(ev)
			}
		}
		if info.Proto == ProtoTCP && info.RST {
			c.rstEvents.push(RSTEvent{
				Iface:      iface,
				LocalAddr:  key.LocalAddr,
				LocalPort:  key.LocalPort,
				RemoteAddr: key.RemoteAddr,
				RemotePort: key.RemotePort,
				At:         ts,
			})
		}
	}
}

// shouldSampleStats reports whether at least interval has elapsed since
// last, i.e. whether captureOn's read loop should call handle.Stats() again.
// A zero last always samples immediately, for the first iteration.
func shouldSampleStats(last, now time.Time, interval time.Duration) bool {
	return last.IsZero() || now.Sub(last) >= interval
}

// record credits n bytes to a flow, creating its counter on first sight, and
// returns that counter. The map lock is released before the counter is
// touched so that a Snapshot never waits on per-flow bookkeeping.
func (c *Capturer) record(key FlowKey, ts time.Time, n uint64, inbound bool) *ByteCounter {
	c.mu.RLock()
	ctr := c.flows[key]
	c.mu.RUnlock()

	if ctr == nil {
		c.mu.Lock()
		// Re-check: another interface's goroutine may have created it while
		// the read lock was down.
		if ctr = c.flows[key]; ctr == nil {
			ctr = &ByteCounter{}
			c.flows[key] = ctr
		}
		c.mu.Unlock()
	}

	ctr.Add(ts, n, inbound)
	return ctr
}

// inspect runs the configured Inspectors against one packet already
// attributed to ctr's flow, stopping at the first one willing to look. It is
// a no-op once ctr no longer needs inspection (see
// ByteCounter.NeedsHostnameInspection). A flow whose ClientHello spans more
// than one segment stays under inspection across several calls — see
// ByteCounter.AddHelloSegment — but is still bounded to one overall attempt:
// once that reassembly finishes or gives up, later packets on the same flow
// are never re-parsed.
//
// A fresh (non-continuation) candidate's payload is extracted up front,
// before any Inspector's Candidate runs, so Candidate can recognise a
// protocol from its own leading bytes instead of assuming a well-known
// port — but only once DatagramLen alone (no extraction needed) has ruled
// out a header-only TCP segment. If no Inspector accepts that first
// extracted payload, the flow's one-shot budget is spent right there rather
// than re-extracting every later packet: a genuine ClientHello (or QUIC
// Initial) is always the first payload-bearing packet a fresh connection
// carries, so this is what keeps a long-lived flow that is never TLS or
// QUIC at all (a plain HTTP download, an SSH session) from paying an
// extraction cost for its whole life instead of just once.
//
// A UDP candidate (QUIC's Initial packet) skips reassembly entirely: one
// datagram is already a complete unit, so it is inspected directly and the
// flow is marked attempted either way, hit or miss, with no continuation
// state to track.
//
// Only the first Inspector in c.cfg.Inspectors whose Candidate accepts a
// given packet is asked: a later one that would also have accepted the same
// packet never gets a look, hit or miss. This holds today because no two
// configured Inspectors' Candidate implementations overlap (see
// DefaultInspectors), but it means combining Inspectors whose candidates do
// overlap is not supported without changing this function.
//
// data is the same zero-copy buffer the capture loop just read; it is used
// here and only here, before the loop's next ZeroCopyReadPacketData call
// invalidates it. extractPayload builds its gopacket.Packet directly over
// data with gopacket.NoCopy, so nothing here copies it — the one copy that
// does happen is each segment's payload going into the flow's
// dpi.HelloAssembler, which has to outlive the next read.
func (c *Capturer) inspect(data []byte, info packetInfo, inbound bool, linkType layers.LinkType, remote netip.Addr, ctr *ByteCounter, ts time.Time) {
	if len(c.cfg.Inspectors) == 0 || !ctr.NeedsHostnameInspection() {
		return
	}

	cand := dpi.CandidatePacket{
		IsTCP:       info.Proto == ProtoTCP,
		SrcPort:     info.SrcPort,
		DstPort:     info.DstPort,
		Outbound:    !inbound,
		DatagramLen: int(info.Bytes),
	}

	inProgress := cand.IsTCP && ctr.HelloInProgress()
	// A continuation must go back to the same inspector that started the
	// reassembly — not just any inspector willing to look — so a second
	// TCP-capable Inspector in the list can never hijack another one's
	// in-progress hello.
	wantInspector := ""
	if inProgress {
		wantInspector = ctr.HelloInspector()
	}

	if !inProgress && cand.IsTCP && cand.DatagramLen <= minPayloadDatagramLen {
		return // header-only TCP segment (SYN, bare ACK, FIN): nothing to extract
	}

	seq, payload, ok := extractPayload(data, linkType, cand.IsTCP)
	if !ok {
		if inProgress {
			ctr.MarkHostnameAttempted()
		}
		return
	}
	cand.Payload = payload

	for _, insp := range c.cfg.Inspectors {
		switch {
		case inProgress:
			if !cand.Outbound || insp.Name() != wantInspector {
				continue // a continuation only cares about this flow's own outbound bytes, on its own inspector
			}
		case !insp.Candidate(cand):
			continue
		}

		if !cand.IsTCP {
			// A single datagram, already complete: no reassembly, no
			// continuation across further calls.
			ctr.MarkHostnameAttempted()
			if host, ok := insp.Inspect(payload); ok {
				ctr.SetHostname(host)
				c.hostnameCache.Put(remote.String(), host, ts)
			}
			return
		}

		ready, done := ctr.AddHelloSegment(insp.Name(), seq, payload)
		if ready != nil {
			if host, ok := insp.Inspect(ready); ok {
				ctr.SetHostname(host)
				c.hostnameCache.Put(remote.String(), host, ts)
			}
		}
		// A candidate packet was examined either way: don't keep retrying
		// this flow once reassembly is done, found a hostname or not.
		if done {
			ctr.MarkHostnameAttempted()
		}
		return
	}

	// A fresh candidate's payload was examined (via Candidate, above) and no
	// Inspector wanted it: this flow's opening payload-bearing packet is
	// never coming back, so there is nothing left to gain by asking again on
	// its next packet.
	if !inProgress {
		ctr.MarkHostnameAttempted()
	}
}

// inspectPassive runs the configured PassiveInspectors against every
// packet, independent of any flow's own hostname state — a DNS resolver
// flow keeps carrying new, unrelated query/response pairs for its whole
// life, unlike a single ClientHello. Candidate keeps this cheap for every
// packet that isn't DNS.
func (c *Capturer) inspectPassive(data []byte, info packetInfo, linkType layers.LinkType, ts time.Time) {
	if len(c.cfg.PassiveInspectors) == 0 {
		return
	}

	cand := dpi.CandidatePacket{
		IsTCP:       info.Proto == ProtoTCP,
		SrcPort:     info.SrcPort,
		DstPort:     info.DstPort,
		DatagramLen: int(info.Bytes),
	}

	for _, insp := range c.cfg.PassiveInspectors {
		if !insp.Candidate(cand) {
			continue
		}

		_, payload, ok := extractPayload(data, linkType, cand.IsTCP)
		if !ok {
			continue
		}
		if cand.IsTCP {
			// DNS-over-TCP prefixes each message with its own 2-byte length;
			// strip it so Inspect always sees one bare message, the same as
			// the UDP case.
			if len(payload) < 2 {
				continue
			}
			payload = payload[2:]
		}

		for _, f := range insp.Inspect(payload) {
			c.hostnameCache.Put(f.IP, f.Hostname, ts)
		}
		if qi, ok := insp.(dpi.QueryPassiveInspector); ok {
			for _, f := range qi.InspectQuery(payload, info.Src.String(), info.Dst.String(), ts) {
				c.dnsQueries.push(f)
				if c.logFeed != nil {
					c.logFeed.sendDNSQuery(f)
				}
			}
		}
		if ei, ok := insp.(dpi.ErrorPassiveInspector); ok {
			for _, f := range ei.InspectError(payload, info.Src.String(), ts) {
				c.dnsErrors.push(f)
			}
		}
	}
}

// extractPayload decodes data with the stock gopacket TCP/UDP decoder — not
// the fast transportPorts path flowDecoder uses for every packet, see
// decode.go — to recover the application-layer payload (and, for TCP, the
// sequence number hello reassembly needs). It is only called for packets
// that already passed Candidate or belong to a flow already mid reassembly,
// so this second decode's cost stays bounded to a handful of packets per new
// connection.
func extractPayload(data []byte, linkType layers.LinkType, isTCP bool) (seq uint32, payload []byte, ok bool) {
	packet := gopacket.NewPacket(data, linkType, gopacket.NoCopy)
	if isTCP {
		tcp, isTCP := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !isTCP {
			return 0, nil, false
		}
		return tcp.Seq, tcp.LayerPayload(), true
	}
	udp, isUDP := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !isUDP {
		return 0, nil, false
	}
	return 0, udp.LayerPayload(), true
}

// Evict drops every flow last seen before the cutoff, except any in keep, and
// reports how many it removed.
//
// Nothing else ever removes a flow, so without this the table grows by one
// counter per connection the host has ever made and never shrinks — a leak
// that only shows up on a long run. The aggregator calls it with the grace
// period's cutoff, once a flow is too stale to appear in the UI at all — but
// an idle flow can still back a connection procinfo reports as open, and
// losing its counters would zero out a live connection's totals rather than
// just stop showing a vanished one. keep is that set of still-open
// connections' flow keys, spared regardless of how long they have been
// quiet; a packet arriving on a genuinely evicted flow afterwards simply
// starts a fresh counter, which is the same thing the UI would show for a
// brand new connection.
func (c *Capturer) Evict(before time.Time, keep map[FlowKey]struct{}) int {
	// Snapshot the candidate keys under a read lock first: LastSeen on every
	// counter would otherwise serialise against the write lock the hot record
	// path also needs, for the whole sweep rather than just the deletions.
	c.mu.RLock()
	stale := make([]FlowKey, 0, len(c.flows))
	for k, ctr := range c.flows {
		if _, spared := keep[k]; spared {
			continue
		}
		if ctr.LastSeen().Before(before) {
			stale = append(stale, k)
		}
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	n := 0
	for _, k := range stale {
		// Re-check staleness under the write lock: a flow may have seen a
		// packet between the snapshot above and taking this lock, and that
		// activity must not be discarded.
		ctr, ok := c.flows[k]
		if !ok || !ctr.LastSeen().Before(before) {
			continue
		}
		delete(c.flows, k)
		n++
	}
	return n
}

// Snapshot returns a point-in-time copy of every flow's counters, for the
// aggregator to join against the process map.
func (c *Capturer) Snapshot(now time.Time) map[FlowKey]FlowStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make(map[FlowKey]FlowStats, len(c.flows))
	for k, ctr := range c.flows {
		in, outB := ctr.Totals()
		rIn, rOut := ctr.Rates(now)
		out[k] = FlowStats{
			BytesIn:    in,
			BytesOut:   outB,
			RateInBps:  rIn,
			RateOutBps: rOut,
			LastSeen:   ctr.LastSeen(),
			Hostname:   ctr.Hostname(),
			Iface:      k.Iface,
		}
	}
	return out
}

// FlowStats is an immutable snapshot of one flow's counters.
type FlowStats struct {
	BytesIn    uint64
	BytesOut   uint64
	RateInBps  float64
	RateOutBps float64
	LastSeen   time.Time
	// Hostname is the hostname DPI identified for this flow, or "" if none
	// has been found.
	Hostname string
	// Iface is the name of the interface this flow was captured on.
	Iface string
}

// PacketStats is one interface's cumulative pcap statistics, sampled
// periodically from pcap.Handle.Stats() — cumulative since the handle was
// opened, so it maps directly onto a monotonic cumulative sum metric.
type PacketStats struct {
	Received  int
	Dropped   int
	IfDropped int
}

// ListInterfaces returns the interfaces libpcap can capture on. Requires root.
func ListInterfaces() ([]string, error) {
	names, err := pcapdrv.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("pcapdrv.FindAllDevs: %w", err)
	}
	return names, nil
}
