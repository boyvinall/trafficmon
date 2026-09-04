// Package dpi looks inside a flow's packets for a hostname the remote
// endpoint identified itself with — a TLS ClientHello's SNI extension today,
// with more protocols (HTTP's Host header, QUIC's Initial SNI, …) expected to
// follow. It is deliberately separate from capture: capture's read loop stays
// a thin, allocation-free byte-accounting path, and every inspector plugs
// into the one seam below without that loop needing protocol knowledge.
package dpi

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
}

// Inspector examines packets of one flow and may report a hostname it found
// for the flow's remote endpoint.
type Inspector interface {
	// Name identifies the inspector, for logs and future metrics.
	Name() string

	// Candidate reports, cheaply, whether a packet is worth the cost of
	// Inspect. It must not itself touch the payload.
	Candidate(p CandidatePacket) bool

	// Inspect examines payload — a flow's application-layer bytes, already
	// reassembled across however many TCP segments they arrived in — and
	// returns the hostname it found, if any.
	Inspect(payload []byte) (hostname string, ok bool)
}

// DefaultInspectors returns the inspector set Capturer runs with unless a
// Config overrides it.
func DefaultInspectors() []Inspector {
	return []Inspector{NewTLSSNIInspector()}
}
