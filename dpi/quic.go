package dpi

import "github.com/cuonglm/quicsni"

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
	return !p.IsTCP && p.Outbound && p.DstPort == port443 && p.DatagramLen >= minInitialDatagramLen
}

// Inspect implements Inspector.
func (q *QUICSNIInspector) Inspect(payload []byte) (hostname string, ok bool) {
	defer recoverPanic()

	chi, err := quicsni.ReadClientHello(payload)
	if err != nil || chi.ServerName == "" {
		return "", false
	}
	return chi.ServerName, true
}
