package dpi

import "github.com/cuonglm/quicsni"

// quicPort is the well-known port for QUIC-wrapped traffic (HTTP/3). A QUIC
// connection negotiated on any other port goes undetected in this first
// pass, the same caveat tlsPort already carries for TLS.
const quicPort = 443

// minInitialDatagramLen is RFC 9000 §14.1's floor on a client's UDP datagram
// carrying an Initial packet: it must be padded to at least this size, so
// anything shorter cannot be one.
const minInitialDatagramLen = 1200

// QUICSNIInspector extracts the SNI extension from the TLS ClientHello
// carried inside a QUIC Initial packet's CRYPTO frame.
type QUICSNIInspector struct{}

// NewQUICSNIInspector creates a QUICSNIInspector.
func NewQUICSNIInspector() *QUICSNIInspector { return &QUICSNIInspector{} }

// Name implements Inspector.
func (q *QUICSNIInspector) Name() string { return "quic-sni" }

// Candidate implements Inspector.
func (q *QUICSNIInspector) Candidate(p CandidatePacket) bool {
	return !p.IsTCP && p.Outbound && p.DstPort == quicPort && p.DatagramLen >= minInitialDatagramLen
}

// Inspect implements Inspector.
func (q *QUICSNIInspector) Inspect(payload []byte) (hostname string, ok bool) {
	// quicsni.ReadClientHello parses attacker-controlled bytes (QUIC header
	// fields, then the unprotected TLS ClientHello); a malformed or truncated
	// packet must not be allowed to take the capture loop down with it.
	defer func() {
		if recover() != nil {
			hostname, ok = "", false
		}
	}()

	chi, err := quicsni.ReadClientHello(payload)
	if err != nil || chi.ServerName == "" {
		return "", false
	}
	return chi.ServerName, true
}
