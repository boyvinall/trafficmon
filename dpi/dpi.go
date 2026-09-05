// Package dpi looks inside a flow's packets for a hostname the remote
// endpoint identified itself with — a TLS or QUIC ClientHello's SNI
// extension — plus, via PassiveInspector, hostnames DNS answers reveal for
// endpoints other than the flow they arrived on. It is deliberately separate
// from capture: capture's read loop stays a thin, allocation-free
// byte-accounting path, and every inspector plugs into one of the two seams
// below without that loop needing protocol knowledge.
package dpi

import "time"

// recoverPanic recovers from a panic in an Inspect implementation, deferred
// as `defer recoverPanic()`. Every Inspect parses bytes the remote endpoint
// controls — a malformed or truncated record must not be allowed to take the
// capture loop down with it — and none of them assign their named results
// before the parse that might panic, so recovering here is enough: the
// results are still at their zero value.
func recoverPanic() {
	recover() //nolint:errcheck // discarding the panic value is the point
}

// CandidatePacket is the cheap, already-decoded slice of one packet's
// metadata an Inspector's Candidate uses to decide whether Inspect is worth
// its cost. It carries nothing that requires touching the payload — callers
// build it from data they already have.
type CandidatePacket struct {
	IsTCP   bool
	SrcPort uint16
	DstPort uint16
	// Outbound is true if the packet is leaving the local host — the
	// direction a TLS ClientHello (or an HTTP request) travels.
	Outbound bool
	// DatagramLen is the whole IP datagram's size as reported by its own
	// header — the real size, not however much of it SnapLen actually
	// captured. It exists to cheaply tell a header-only TCP segment (a SYN,
	// a bare ACK, a FIN) apart from one carrying payload: those cap out at a
	// few dozen bytes even with a full set of TCP options, while anything
	// worth inspecting is bigger by a wide margin. Candidate must not use it
	// as a proxy for how many bytes were actually captured — that is what
	// makes Inspect's own truncation check (on the real data slice)
	// necessary in addition to this one.
	DatagramLen int
	// Payload is this packet's already-extracted application-layer bytes —
	// the same slice Inspect itself would receive — so Candidate can
	// recognise a protocol by its own leading bytes (TLS's ContentType and
	// version, QUIC's long-header form bit) instead of assuming a
	// well-known port: a TLS or QUIC handshake on a non-443 port (STARTTLS,
	// or a custom port like gRPC-over-TLS on 4317) is otherwise
	// indistinguishable from one that will never be TLS at all. It is the
	// same zero-copy buffer Capturer's read loop holds; like Inspect's
	// payload, Candidate must not retain it past its own call. Nil for a
	// packet Capturer decided was not worth extracting at all (a
	// header-only TCP segment, most obviously) — Candidate must handle
	// that case rather than assume it is always populated.
	Payload []byte
}

// Inspector examines packets of one flow and may report a hostname it found
// for the flow's remote endpoint.
type Inspector interface {
	// Name identifies the inspector, for logs and future metrics.
	Name() string

	// Candidate reports, cheaply, whether a packet is worth the cost of
	// Inspect: cheaply meaning no protocol parsing, just recognising the
	// shape (direction, size, and CandidatePacket.Payload's leading bytes)
	// that Inspect's own real parse would need to succeed.
	Candidate(p CandidatePacket) bool

	// Inspect examines payload — a flow's application-layer bytes, already
	// reassembled across however many TCP segments they arrived in — and
	// returns the hostname it found, if any.
	Inspect(payload []byte) (hostname string, ok bool)
}

// DefaultInspectors returns the inspector set Capturer runs with unless a
// Config overrides it.
func DefaultInspectors() []Inspector {
	return []Inspector{NewTLSSNIInspector(), NewQUICSNIInspector()}
}

// HostnameFinding is one IP-to-hostname mapping a PassiveInspector observed —
// unlike Inspector, the endpoint the hostname describes is not necessarily
// the flow the packet arrived on.
type HostnameFinding struct {
	IP       string
	Hostname string
}

// PassiveInspector examines packets for hostnames of other connections'
// endpoints — a DNS answer being the obvious source — rather than the flow
// it arrived on. Capturer feeds every finding straight into HostnameCache
// instead of a single flow's own hostname.
type PassiveInspector interface {
	// Name identifies the inspector, for logs and future metrics.
	Name() string

	// Candidate reports, cheaply, whether a packet is worth the cost of
	// Inspect. It must not itself touch the payload.
	Candidate(p CandidatePacket) bool

	// Inspect examines a flow's application-layer bytes and returns every
	// IP-to-hostname mapping it found.
	Inspect(payload []byte) []HostnameFinding
}

// DefaultPassiveInspectors returns the passive inspector set Capturer runs
// with unless a Config overrides it.
func DefaultPassiveInspectors() []PassiveInspector {
	return []PassiveInspector{NewDNSAnswerInspector(), NewDNSQueryInspector()}
}

// QueryFinding is one DNS query observed leaving the host toward a resolver —
// unlike HostnameFinding, it names a query in flight rather than a hostname
// learned from a response, and is never written into HostnameCache.
type QueryFinding struct {
	Name       string
	QType      string
	ClientAddr string
	ServerAddr string
	At         time.Time
}

// QueryPassiveInspector is implemented by a PassiveInspector that also
// reports the DNS queries it sees, in addition to whatever it reports
// through Inspect. It is a separate interface rather than a wider
// PassiveInspector.Inspect return type because InspectQuery needs the
// packet's addresses and timestamp, which Inspect's payload-only signature
// does not carry, and because most PassiveInspectors have no queries to
// report at all.
type QueryPassiveInspector interface {
	PassiveInspector

	// InspectQuery examines payload — the same complete DNS message Inspect
	// would receive — and returns one QueryFinding per question, if payload
	// is a query rather than a response.
	InspectQuery(payload []byte, clientAddr, serverAddr string, at time.Time) []QueryFinding
}
