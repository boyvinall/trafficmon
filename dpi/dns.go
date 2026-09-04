package dpi

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// dnsPort is the well-known port for DNS.
const dnsPort = 53

// DNSAnswerInspector learns hostnames passively from DNS responses: an A or
// AAAA answer names the IP a later, unrelated flow may connect to. It is
// named to avoid confusion with the separate dns package, which does active
// reverse lookups rather than passive capture.
type DNSAnswerInspector struct{}

// NewDNSAnswerInspector creates a DNSAnswerInspector.
func NewDNSAnswerInspector() *DNSAnswerInspector { return &DNSAnswerInspector{} }

// Name implements PassiveInspector.
func (d *DNSAnswerInspector) Name() string { return "dns-answer" }

// Candidate implements PassiveInspector. Only a response (from port 53) has
// answers worth learning from — a query alone names nothing yet.
func (d *DNSAnswerInspector) Candidate(p CandidatePacket) bool {
	return p.SrcPort == dnsPort
}

// Inspect implements PassiveInspector. payload is one complete DNS message:
// capture strips DNS-over-TCP's 2-byte length prefix before calling this, so
// Inspect never has to know which transport it arrived on. A message split
// across TCP segments goes undetected — the same accepted limitation
// HelloAssembler documents for TLS.
func (d *DNSAnswerInspector) Inspect(payload []byte) (findings []HostnameFinding) {
	// layers.DNS parses attacker-controlled bytes; a malformed or truncated
	// message must not be allowed to take the capture loop down with it.
	defer func() {
		if recover() != nil {
			findings = nil
		}
	}()

	var msg layers.DNS
	if err := msg.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil || !msg.QR {
		return nil
	}

	for _, a := range msg.Answers {
		if a.Type != layers.DNSTypeA && a.Type != layers.DNSTypeAAAA || a.IP == nil {
			continue
		}
		findings = append(findings, HostnameFinding{IP: a.IP.String(), Hostname: string(a.Name)})
	}
	return findings
}
