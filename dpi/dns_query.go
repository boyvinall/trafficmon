package dpi

import (
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// DNSQueryInspector captures outbound DNS queries themselves, the mirror
// image of DNSAnswerInspector's hostname learning from responses: a query
// names what a process is about to look up, before any answer — or
// connection to the name it resolves to — exists yet.
type DNSQueryInspector struct{}

// NewDNSQueryInspector creates a DNSQueryInspector.
func NewDNSQueryInspector() *DNSQueryInspector { return &DNSQueryInspector{} }

// Name implements PassiveInspector.
func (d *DNSQueryInspector) Name() string { return "dns-query" }

// Candidate implements PassiveInspector. A query is addressed to a resolver
// on port 53 — the mirror of DNSAnswerInspector's SrcPort check.
func (d *DNSQueryInspector) Candidate(p CandidatePacket) bool {
	return p.DstPort == dnsPort
}

// Inspect implements PassiveInspector. DNSQueryInspector has nothing to add
// to HostnameCache — its findings are queries, reported through InspectQuery
// instead — so this always returns nil.
func (d *DNSQueryInspector) Inspect([]byte) []HostnameFinding {
	return nil
}

// InspectQuery implements QueryPassiveInspector. payload is one complete DNS
// message, the same as Inspect receives — capture strips DNS-over-TCP's
// 2-byte length prefix before calling either.
func (d *DNSQueryInspector) InspectQuery(payload []byte, clientAddr, serverAddr string, at time.Time) (findings []QueryFinding) {
	defer recoverPanic()

	var msg layers.DNS
	if err := msg.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil || msg.QR {
		return nil
	}

	for _, q := range msg.Questions {
		findings = append(findings, QueryFinding{
			Name:       string(q.Name),
			QType:      q.Type.String(),
			ClientAddr: clientAddr,
			ServerAddr: serverAddr,
			At:         at,
		})
	}
	return findings
}
