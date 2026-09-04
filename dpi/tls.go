package dpi

import "github.com/dreadl0ck/tlsx"

// tlsPort is the well-known port for TLS-wrapped traffic. A ClientHello sent
// to any other port (STARTTLS, custom ports) goes undetected in this first
// pass.
const tlsPort = 443

// minClientHelloDatagramLen excludes header-only TCP segments (SYN, bare
// ACK, FIN) without rejecting a genuine ClientHello. Even a SYN with every
// TCP option set is under 120 bytes of real IP datagram; a ClientHello
// carries a cipher suite list and several extensions, so it is reliably
// well past that in practice.
const minClientHelloDatagramLen = 200

// TLSSNIInspector extracts the SNI extension from a TLS ClientHello.
type TLSSNIInspector struct{}

// NewTLSSNIInspector creates a TLSSNIInspector.
func NewTLSSNIInspector() *TLSSNIInspector { return &TLSSNIInspector{} }

// Name implements Inspector.
func (t *TLSSNIInspector) Name() string { return "tls-sni" }

// Candidate implements Inspector.
func (t *TLSSNIInspector) Candidate(p CandidatePacket) bool {
	return p.IsTCP && p.Outbound && p.DstPort == tlsPort && p.DatagramLen > minClientHelloDatagramLen
}

// Inspect implements Inspector.
func (t *TLSSNIInspector) Inspect(payload []byte) (hostname string, ok bool) {
	// tlsx parses attacker-controlled bytes; a malformed or truncated record
	// must not be allowed to take the capture loop down with it.
	defer func() {
		if recover() != nil {
			hostname, ok = "", false
		}
	}()

	var ch tlsx.ClientHelloBasic
	if err := ch.Unmarshal(payload); err != nil || ch.SNI == "" {
		return "", false
	}
	return ch.SNI, true
}
