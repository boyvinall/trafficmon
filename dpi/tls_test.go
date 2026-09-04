package dpi

import (
	"encoding/binary"
	"testing"
)

// buildClientHello hand-encodes a minimal TLS 1.2 ClientHello record
// carrying a single server_name (SNI) extension, or none if sni is "".
func buildClientHello(sni string) []byte {
	var extensions []byte
	if sni != "" {
		nameEntry := append([]byte{0x00}, u16(uint16(len(sni)))...) // host_name type + length
		nameEntry = append(nameEntry, sni...)
		serverNameList := append(u16(uint16(len(nameEntry))), nameEntry...)
		ext := append([]byte{0x00, 0x00}, u16(uint16(len(serverNameList)))...) // extension type 0 = server_name
		ext = append(ext, serverNameList...)
		extensions = append(extensions, ext...)
	}

	body := []byte{0x03, 0x03}               // client version: TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session ID length = 0
	body = append(body, u16(2)...)           // cipher suites length
	body = append(body, 0x13, 0x01)          // TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)          // compression methods: len=1, null
	body = append(body, u16(uint16(len(extensions)))...)
	body = append(body, extensions...)

	handshake := append([]byte{0x01}, u24(uint32(len(body)))...) // ClientHello
	handshake = append(handshake, body...)

	record := []byte{0x16, 0x03, 0x01} // Handshake, TLS 1.0 record version
	record = append(record, u16(uint16(len(handshake)))...)
	record = append(record, handshake...)
	return record
}

func u16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func u24(v uint32) []byte {
	return []byte{byte(v >> 16), byte(v >> 8), byte(v)}
}

func TestTLSSNIInspectorInspect(t *testing.T) {
	inspector := NewTLSSNIInspector()

	t.Run("extracts SNI", func(t *testing.T) {
		host, ok := inspector.Inspect(buildClientHello("example.com"))
		if !ok || host != "example.com" {
			t.Fatalf("Inspect() = %q, %v; want %q, true", host, ok, "example.com")
		}
	})

	t.Run("no SNI extension", func(t *testing.T) {
		if _, ok := inspector.Inspect(buildClientHello("")); ok {
			t.Fatal("Inspect() = ok=true for a ClientHello with no SNI extension")
		}
	})

	t.Run("not TLS at all", func(t *testing.T) {
		garbage := make([]byte, 100)
		for i := range garbage {
			garbage[i] = byte(i)
		}
		if _, ok := inspector.Inspect(garbage); ok {
			t.Fatal("Inspect() = ok=true for garbage bytes")
		}
	})

	t.Run("truncated", func(t *testing.T) {
		full := buildClientHello("www.this-hostname-is-long-enough-to-exceed-a-short-truncation.example.com")
		if len(full) <= 128 {
			t.Fatalf("test fixture too short: %d bytes, want > 128", len(full))
		}

		if _, ok := inspector.Inspect(full[:128]); ok {
			t.Fatal("Inspect() = ok=true for a ClientHello truncated to 128 bytes")
		}
		if _, ok := inspector.Inspect(full); !ok {
			t.Fatal("Inspect() = ok=false for a complete ClientHello")
		}
	})
}

func TestTLSSNIInspectorCandidate(t *testing.T) {
	tests := []struct {
		name string
		p    CandidatePacket
		want bool
	}{
		{"matches", CandidatePacket{IsTCP: true, Outbound: true, DstPort: 443, DatagramLen: 500}, true},
		{"inbound", CandidatePacket{IsTCP: true, Outbound: false, DstPort: 443, DatagramLen: 500}, false},
		{"wrong port", CandidatePacket{IsTCP: true, Outbound: true, DstPort: 8443, DatagramLen: 500}, false},
		{"not TCP", CandidatePacket{IsTCP: false, Outbound: true, DstPort: 443, DatagramLen: 500}, false},
		{"too short for a real ClientHello", CandidatePacket{IsTCP: true, Outbound: true, DstPort: 443, DatagramLen: 10}, false},
		{"SYN-sized, even with a full TCP option set", CandidatePacket{IsTCP: true, Outbound: true, DstPort: 443, DatagramLen: 100}, false},
	}

	inspector := NewTLSSNIInspector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inspector.Candidate(tt.p); got != tt.want {
				t.Errorf("Candidate(%+v) = %v, want %v", tt.p, got, tt.want)
			}
		})
	}
}
