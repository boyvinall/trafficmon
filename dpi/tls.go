package dpi

import "github.com/dreadl0ck/tlsx"

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
	return p.IsTCP && p.Outbound && p.DstPort == port443 && p.DatagramLen > minClientHelloDatagramLen
}

// Inspect implements Inspector.
func (t *TLSSNIInspector) Inspect(payload []byte) (hostname string, ok bool) {
	defer recoverPanic()

	var ch tlsx.ClientHelloBasic
	if err := ch.Unmarshal(payload); err != nil || ch.SNI == "" {
		return "", false
	}
	return ch.SNI, true
}
