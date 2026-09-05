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

// Candidate implements Inspector. Recognising a QUIC Initial packet by its
// own bytes, rather than assuming port 443, is what lets this also catch
// QUIC negotiated on any other port.
func (q *QUICSNIInspector) Candidate(p CandidatePacket) bool {
	return !p.IsTCP && p.Outbound && p.DatagramLen >= minInitialDatagramLen && looksLikeQUICInitial(p.Payload)
}

// looksLikeQUICInitial reports whether b starts with a QUIC long-header
// packet of type Initial: RFC 9000 §17.2's Header Form and Fixed bits (the
// top two bits of the first byte) are both 1, and the following 2 bits (the
// Long Packet Type) are 0 for Initial -- together, the top nibble is 0xC
// regardless of the packet-number-length bits below it, which vary. The
// version field (the next 4 bytes) is never all-zero for a real Initial —
// that encoding is reserved for version negotiation -- so this also requires
// a nonzero version. Any false positive still has to survive quicsni's real
// parse in Inspect.
func looksLikeQUICInitial(b []byte) bool {
	const longHeaderInitialNibble = 0xC0
	return len(b) >= 5 && b[0]&0xF0 == longHeaderInitialNibble && (b[1] != 0 || b[2] != 0 || b[3] != 0 || b[4] != 0)
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
