package dpi

import (
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

func TestDNSQueryInspectorInspectQuery(t *testing.T) {
	inspector := NewDNSQueryInspector()
	at := time.Now()

	t.Run("single question", func(t *testing.T) {
		msg := &layers.DNS{QR: false}
		msg.Questions = append(msg.Questions, layers.DNSQuestion{
			Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
		})

		got := inspector.InspectQuery(dnsMessage(t, msg), "10.0.0.1", "8.8.8.8", at)
		want := []QueryFinding{
			{Name: "example.com", QType: "A", ClientAddr: "10.0.0.1", ServerAddr: "8.8.8.8", At: at},
		}
		if len(got) != len(want) {
			t.Fatalf("InspectQuery() = %+v, want %+v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("InspectQuery()[%d] = %+v, want %+v", i, got[i], want[i])
			}
		}
	})

	t.Run("multiple questions", func(t *testing.T) {
		msg := &layers.DNS{QR: false}
		msg.Questions = append(msg.Questions,
			layers.DNSQuestion{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
			layers.DNSQuestion{Name: []byte("example.com"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
		)

		got := inspector.InspectQuery(dnsMessage(t, msg), "10.0.0.1", "8.8.8.8", at)
		want := []QueryFinding{
			{Name: "example.com", QType: "A", ClientAddr: "10.0.0.1", ServerAddr: "8.8.8.8", At: at},
			{Name: "example.com", QType: "AAAA", ClientAddr: "10.0.0.1", ServerAddr: "8.8.8.8", At: at},
		}
		if len(got) != len(want) {
			t.Fatalf("InspectQuery() = %+v, want %+v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("InspectQuery()[%d] = %+v, want %+v", i, got[i], want[i])
			}
		}
	})

	t.Run("answer produces no finding", func(t *testing.T) {
		msg := &layers.DNS{QR: true, ANCount: 0}
		msg.Questions = append(msg.Questions, layers.DNSQuestion{
			Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
		})

		if got := inspector.InspectQuery(dnsMessage(t, msg), "10.0.0.1", "8.8.8.8", at); got != nil {
			t.Fatalf("InspectQuery() = %+v for an answer, want nil", got)
		}
	})

	t.Run("garbage", func(t *testing.T) {
		garbage := make([]byte, 100)
		for i := range garbage {
			garbage[i] = byte(i)
		}
		if got := inspector.InspectQuery(garbage, "10.0.0.1", "8.8.8.8", at); got != nil {
			t.Fatalf("InspectQuery() = %+v for garbage bytes, want nil", got)
		}
	})

	t.Run("Inspect always returns nil", func(t *testing.T) {
		msg := &layers.DNS{QR: false}
		msg.Questions = append(msg.Questions, layers.DNSQuestion{
			Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
		})
		if got := inspector.Inspect(dnsMessage(t, msg)); got != nil {
			t.Fatalf("Inspect() = %+v, want nil", got)
		}
	})
}

func TestDNSQueryInspectorCandidate(t *testing.T) {
	tests := []struct {
		name string
		p    CandidatePacket
		want bool
	}{
		{"query", CandidatePacket{SrcPort: 51000, DstPort: 53}, true},
		{"response", CandidatePacket{SrcPort: 53, DstPort: 51000}, false},
		{"unrelated port", CandidatePacket{SrcPort: 51000, DstPort: 51001}, false},
	}

	inspector := NewDNSQueryInspector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inspector.Candidate(tt.p); got != tt.want {
				t.Errorf("Candidate(%+v) = %v, want %v", tt.p, got, tt.want)
			}
		})
	}
}
