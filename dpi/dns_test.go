package dpi

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// dnsMessage serializes a DNS message (query or response) the same way
// capture's own tests build wire-format packets, via gopacket's serializer.
func dnsMessage(t *testing.T, msg *layers.DNS) []byte {
	t.Helper()

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, msg); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return buf.Bytes()
}

func TestDNSAnswerInspectorInspect(t *testing.T) {
	inspector := NewDNSAnswerInspector()

	t.Run("A and AAAA answers", func(t *testing.T) {
		msg := &layers.DNS{QR: true, ANCount: 2}
		msg.Questions = append(msg.Questions, layers.DNSQuestion{
			Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
		})
		msg.Answers = append(msg.Answers,
			layers.DNSResourceRecord{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, IP: net.IPv4(93, 184, 216, 34)},
			layers.DNSResourceRecord{Name: []byte("example.com"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN, IP: net.ParseIP("2606:2800:21f:cb07:6820:80da:af6b:8b2c")},
		)

		got := inspector.Inspect(dnsMessage(t, msg))
		want := []HostnameFinding{
			{IP: "93.184.216.34", Hostname: "example.com"},
			{IP: "2606:2800:21f:cb07:6820:80da:af6b:8b2c", Hostname: "example.com"},
		}
		if len(got) != len(want) {
			t.Fatalf("Inspect() = %+v, want %+v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("Inspect()[%d] = %+v, want %+v", i, got[i], want[i])
			}
		}
	})

	t.Run("answer name resolves through a CNAME, not the original question", func(t *testing.T) {
		msg := &layers.DNS{QR: true, ANCount: 2}
		msg.Questions = append(msg.Questions, layers.DNSQuestion{
			Name: []byte("www.example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
		})
		msg.Answers = append(msg.Answers,
			layers.DNSResourceRecord{Name: []byte("www.example.com"), Type: layers.DNSTypeCNAME, Class: layers.DNSClassIN, CNAME: []byte("cdn.example.net")},
			layers.DNSResourceRecord{Name: []byte("cdn.example.net"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, IP: net.IPv4(198, 51, 100, 1)},
		)

		got := inspector.Inspect(dnsMessage(t, msg))
		if len(got) != 1 || got[0] != (HostnameFinding{IP: "198.51.100.1", Hostname: "cdn.example.net"}) {
			t.Fatalf("Inspect() = %+v, want a single finding naming the CNAME target, not the original question", got)
		}
	})

	t.Run("query with no answers", func(t *testing.T) {
		msg := &layers.DNS{QR: false}
		msg.Questions = append(msg.Questions, layers.DNSQuestion{
			Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
		})
		if got := inspector.Inspect(dnsMessage(t, msg)); got != nil {
			t.Fatalf("Inspect() = %+v for a query, want nil", got)
		}
	})

	t.Run("garbage", func(t *testing.T) {
		garbage := make([]byte, 100)
		for i := range garbage {
			garbage[i] = byte(i)
		}
		if got := inspector.Inspect(garbage); got != nil {
			t.Fatalf("Inspect() = %+v for garbage bytes, want nil", got)
		}
	})
}

func TestDNSAnswerInspectorCandidate(t *testing.T) {
	tests := []struct {
		name string
		p    CandidatePacket
		want bool
	}{
		{"response", CandidatePacket{SrcPort: 53, DstPort: 51000}, true},
		{"query", CandidatePacket{SrcPort: 51000, DstPort: 53}, false},
		{"unrelated port", CandidatePacket{SrcPort: 51000, DstPort: 51001}, false},
	}

	inspector := NewDNSAnswerInspector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inspector.Candidate(tt.p); got != tt.want {
				t.Errorf("Candidate(%+v) = %v, want %v", tt.p, got, tt.want)
			}
		})
	}
}
