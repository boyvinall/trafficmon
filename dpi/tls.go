package dpi

import "github.com/dreadl0ck/tlsx"

// TLSSNIInspector extracts the SNI extension from a TLS ClientHello.
type TLSSNIInspector struct{}

// NewTLSSNIInspector creates a TLSSNIInspector.
func NewTLSSNIInspector() *TLSSNIInspector { return &TLSSNIInspector{} }

// Name implements Inspector.
func (t *TLSSNIInspector) Name() string { return "tls-sni" }

// Candidate implements Inspector. Recognising a TLS record by its own bytes,
// rather than assuming port 443, is what lets this also catch TLS negotiated
// on any other port -- gRPC-over-TLS on a custom port, say.
func (t *TLSSNIInspector) Candidate(p CandidatePacket) bool {
	return p.IsTCP && p.Outbound && looksLikeTLSClientHello(p.Payload)
}

// looksLikeTLSClientHello reports whether b starts with a TLS record header
// (ContentType = Handshake, legacy major version = 3 -- true of every TLS
// version from 1.0 through 1.3, thanks to version-field ossification) whose
// handshake message is a ClientHello. This is the record layer's own fixed
// layout (RFC 8446 §5.1, §4), not a heuristic: any false positive still has
// to survive tlsx's real parse in Inspect.
func looksLikeTLSClientHello(b []byte) bool {
	const (
		contentTypeHandshake     = 0x16
		legacyMajorVersion       = 0x03
		handshakeTypeClientHello = 0x01
	)
	return len(b) >= 6 && b[0] == contentTypeHandshake && b[1] == legacyMajorVersion && b[5] == handshakeTypeClientHello
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
