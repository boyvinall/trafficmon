package dpi

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// serialize builds a wire-format packet out of the given layers, following
// the same pattern as capture/decode_test.go.
func serialize(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return buf.Bytes()
}

func ethernet(next layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: next,
	}
}

func ipv4(srcPort, dstPort uint16) (*layers.IPv4, *layers.TCP) {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{192, 168, 1, 10},
		DstIP:    net.IP{140, 82, 112, 3},
	}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), PSH: true, ACK: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err) // only fails for an unsupported network layer type, which ip never is
	}
	return ip, tcp
}

// packet wraps payload in Ethernet/IPv4/TCP layers from srcPort to dstPort
// and serializes it.
func packet(t *testing.T, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	ip, tcp := ipv4(srcPort, dstPort)
	return serialize(t, ethernet(layers.EthernetTypeIPv4), ip, tcp, gopacket.Payload(payload))
}

func ipv6(srcPort, dstPort uint16) (*layers.IPv6, *layers.TCP) {
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2606:4700::1111"),
	}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), PSH: true, ACK: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err) // only fails for an unsupported network layer type, which ip never is
	}
	return ip, tcp
}

// packet6 is packet's IPv6 counterpart.
func packet6(t *testing.T, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	ip, tcp := ipv6(srcPort, dstPort)
	return serialize(t, ethernet(layers.EthernetTypeIPv6), ip, tcp, gopacket.Payload(payload))
}

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
		data := packet(t, 51000, 443, buildClientHello("example.com"))
		host, ok := inspector.Inspect(data, layers.LinkTypeEthernet)
		if !ok || host != "example.com" {
			t.Fatalf("Inspect() = %q, %v; want %q, true", host, ok, "example.com")
		}
	})

	t.Run("extracts SNI over IPv6", func(t *testing.T) {
		data := packet6(t, 51000, 443, buildClientHello("example.com"))
		host, ok := inspector.Inspect(data, layers.LinkTypeEthernet)
		if !ok || host != "example.com" {
			t.Fatalf("Inspect() = %q, %v; want %q, true", host, ok, "example.com")
		}
	})

	t.Run("no SNI extension", func(t *testing.T) {
		data := packet(t, 51000, 443, buildClientHello(""))
		if _, ok := inspector.Inspect(data, layers.LinkTypeEthernet); ok {
			t.Fatal("Inspect() = ok=true for a ClientHello with no SNI extension")
		}
	})

	t.Run("not TLS at all", func(t *testing.T) {
		garbage := make([]byte, 100)
		for i := range garbage {
			garbage[i] = byte(i)
		}
		data := packet(t, 51000, 443, garbage)
		if _, ok := inspector.Inspect(data, layers.LinkTypeEthernet); ok {
			t.Fatal("Inspect() = ok=true for garbage bytes")
		}
	})

	t.Run("truncated by SnapLen", func(t *testing.T) {
		// A hostname long enough that the whole ClientHello does not fit in
		// the old 128-byte SnapLen, but comfortably fits in the new one.
		full := packet(t, 51000, 443, buildClientHello("www.this-hostname-is-long-enough-to-exceed-the-old-snaplen.example.com"))
		if len(full) <= 128 {
			t.Fatalf("test fixture too short: %d bytes, want > 128", len(full))
		}

		if _, ok := inspector.Inspect(full[:128], layers.LinkTypeEthernet); ok {
			t.Fatal("Inspect() = ok=true for a ClientHello truncated to the old 128-byte SnapLen")
		}
		if _, ok := inspector.Inspect(full, layers.LinkTypeEthernet); !ok {
			t.Fatal("Inspect() = ok=false for a ClientHello within the new 1600-byte SnapLen")
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
