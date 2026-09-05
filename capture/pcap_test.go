package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/boyvinall/trafficmon/dpi"
)

// fakeInspector is a dpi.Inspector test double: it always accepts candidates
// and returns a fixed hostname (or none), while counting how many times
// Inspect was actually called.
type fakeInspector struct {
	hostname string
	ok       bool
	calls    int
}

func (f *fakeInspector) Name() string { return "fake" }

func (f *fakeInspector) Candidate(dpi.CandidatePacket) bool { return true }

func (f *fakeInspector) Inspect([]byte) (string, bool) {
	f.calls++
	return f.hostname, f.ok
}

// fakePassiveInspector is a dpi.PassiveInspector test double: it always
// accepts candidates and returns a fixed set of findings, while counting how
// many times Inspect was actually called.
type fakePassiveInspector struct {
	findings []dpi.HostnameFinding
	calls    int
}

func (f *fakePassiveInspector) Name() string { return "fake-passive" }

func (f *fakePassiveInspector) Candidate(dpi.CandidatePacket) bool { return true }

func (f *fakePassiveInspector) Inspect([]byte) []dpi.HostnameFinding {
	f.calls++
	return f.findings
}

func TestCapturerRecordAndSnapshot(t *testing.T) {
	c := New(DefaultConfig())
	now := time.Now().Truncate(time.Second)

	key := FlowKey{
		LocalAddr:  mustAddr(t, "192.168.1.10"),
		LocalPort:  51000,
		RemoteAddr: mustAddr(t, "140.82.112.3"),
		RemotePort: 443,
		Proto:      ProtoTCP,
	}

	// Two packets of each direction on one flow, plus one on another, to
	// prove the map keys them apart and the counters accumulate.
	c.record(key, now, 1000, false)
	c.record(key, now, 4000, true)
	c.record(key, now, 500, false)

	other := key
	other.RemotePort = 80
	c.record(other, now, 42, true)

	snap := c.Snapshot(now)
	if len(snap) != 2 {
		t.Fatalf("Snapshot() has %d flows, want 2", len(snap))
	}

	got := snap[key]
	if got.BytesOut != 1500 || got.BytesIn != 4000 {
		t.Errorf("totals = (in %d, out %d), want (4000, 1500)", got.BytesIn, got.BytesOut)
	}
	if want := 4000.0 / rateWindow.Seconds(); got.RateInBps != want {
		t.Errorf("RateInBps = %.1f, want %.1f", got.RateInBps, want)
	}
	if !got.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %s, want %s", got.LastSeen, now)
	}
}

func TestCapturerRecordReusesCounterPerFlow(t *testing.T) {
	c := New(DefaultConfig())
	now := time.Now()

	key := FlowKey{LocalAddr: mustAddr(t, "10.0.0.1"), LocalPort: 1, Proto: ProtoUDP}
	c.record(key, now, 1, true)
	first := c.flows[key]
	c.record(key, now, 1, true)

	if c.flows[key] != first {
		t.Fatal("record() replaced the counter for an existing flow")
	}
	if len(c.flows) != 1 {
		t.Fatalf("flow map has %d entries, want 1", len(c.flows))
	}
}

func TestCapturerInspectSetsHostnameAndCachesByIP(t *testing.T) {
	c := New(DefaultConfig())
	now := time.Now()

	key := FlowKey{
		LocalAddr:  mustAddr(t, "192.168.1.10"),
		LocalPort:  51000,
		RemoteAddr: mustAddr(t, "140.82.112.3"),
		RemotePort: 443,
		Proto:      ProtoTCP,
	}
	ctr := c.record(key, now, 1000, false)

	insp := &fakeInspector{hostname: "example.com", ok: true}
	c.cfg.Inspectors = []dpi.Inspector{insp}

	data := serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51000, DstPort: 443, PSH: true, ACK: true},
		gopacket.Payload(tlsClientHelloRecord("example.com")))
	info := packetInfo{Proto: ProtoTCP, SrcPort: 51000, DstPort: 443, Bytes: uint64(len(data) - 14)}
	c.inspect(data, info, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)

	if got := ctr.Hostname(); got != "example.com" {
		t.Fatalf("ByteCounter.Hostname() = %q, want %q", got, "example.com")
	}
	if got, ok := c.hostnameCache.Get(key.RemoteAddr.String(), now); !ok || got != "example.com" {
		t.Fatalf("HostnameCache Get() = %q, %v; want %q, true", got, ok, "example.com")
	}

	// A second packet on the same flow must not re-invoke the inspector: the
	// hostname is already known.
	c.inspect(data, info, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)
	if insp.calls != 1 {
		t.Errorf("Inspect() called %d times, want 1", insp.calls)
	}
}

// TestCapturerInspectHandlesUDPCandidateWithoutReassembly covers a
// UDP-based Inspector (QUIC's Initial packet): one datagram is already a
// complete unit, so it must be inspected directly, with no HelloAssembler
// continuation state and no dependence on the TCP-specific reassembly path.
func TestCapturerInspectHandlesUDPCandidateWithoutReassembly(t *testing.T) {
	c := New(DefaultConfig())
	now := time.Now()

	key := FlowKey{
		LocalAddr:  mustAddr(t, "192.168.1.10"),
		LocalPort:  51000,
		RemoteAddr: mustAddr(t, "140.82.112.3"),
		RemotePort: 443,
		Proto:      ProtoUDP,
	}
	ctr := c.record(key, now, 1200, false)

	insp := &fakeInspector{hostname: "quic.example.com", ok: true}
	c.cfg.Inspectors = []dpi.Inspector{insp}

	data := serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolUDP),
		&layers.UDP{SrcPort: 51000, DstPort: 443},
		gopacket.Payload(bytes.Repeat([]byte{0xAB}, 1200)))
	info := packetInfo{Proto: ProtoUDP, SrcPort: 51000, DstPort: 443, Bytes: uint64(len(data) - 14)}
	c.inspect(data, info, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)

	if got := ctr.Hostname(); got != "quic.example.com" {
		t.Fatalf("Hostname() = %q, want %q", got, "quic.example.com")
	}
	if got, ok := c.hostnameCache.Get(key.RemoteAddr.String(), now); !ok || got != "quic.example.com" {
		t.Fatalf("HostnameCache Get() = %q, %v; want %q, true", got, ok, "quic.example.com")
	}
	if ctr.HelloInProgress() {
		t.Error("HelloInProgress() = true after a UDP candidate; UDP must not use TLS reassembly")
	}

	// A second datagram on the same flow must not re-invoke the inspector:
	// the flow was marked attempted after the first, complete datagram.
	c.inspect(data, info, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)
	if insp.calls != 1 {
		t.Errorf("Inspect() called %d times, want 1", insp.calls)
	}
}

// TestCapturerInspectPassiveFeedsHostnameCache proves a PassiveInspector
// finding lands in HostnameCache directly, with no flow/ByteCounter
// involvement at all — the IP it names need not be (and here isn't) the
// flow's own remote address.
func TestCapturerInspectPassiveFeedsHostnameCache(t *testing.T) {
	c := New(DefaultConfig())
	now := time.Now()

	insp := &fakePassiveInspector{findings: []dpi.HostnameFinding{
		{IP: "93.184.216.34", Hostname: "example.com"},
	}}
	c.cfg.PassiveInspectors = []dpi.PassiveInspector{insp}

	data := serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolUDP),
		&layers.UDP{SrcPort: 53, DstPort: 51000},
		gopacket.Payload([]byte("dns response bytes")))
	info := packetInfo{Proto: ProtoUDP, SrcPort: 53, DstPort: 51000, Bytes: uint64(len(data) - 14)}
	c.inspectPassive(data, info, layers.LinkTypeEthernet, now)

	if got, ok := c.hostnameCache.Get("93.184.216.34", now); !ok || got != "example.com" {
		t.Fatalf("HostnameCache Get() = %q, %v; want %q, true", got, ok, "example.com")
	}
	if insp.calls != 1 {
		t.Errorf("Inspect() called %d times, want 1", insp.calls)
	}
}

// TestCapturerInspectPassiveSkipsInspectorsThatRejectTheCandidate proves
// Candidate actually gates each PassiveInspector independently: one that
// rejects the packet must never have Inspect called on it, while another
// that accepts the same packet still runs normally.
func TestCapturerInspectPassiveSkipsInspectorsThatRejectTheCandidate(t *testing.T) {
	c := New(DefaultConfig())
	now := time.Now()

	accepting := &fakePassiveInspector{findings: []dpi.HostnameFinding{{IP: "10.0.0.1", Hostname: "h"}}}
	c.cfg.PassiveInspectors = []dpi.PassiveInspector{&candidateRejectingPassiveInspector{}, accepting}

	data := serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolUDP),
		&layers.UDP{SrcPort: 12345, DstPort: 54321}, gopacket.Payload([]byte("x")))
	info := packetInfo{Proto: ProtoUDP, SrcPort: 12345, DstPort: 54321, Bytes: uint64(len(data) - 14)}
	c.inspectPassive(data, info, layers.LinkTypeEthernet, now) // must not panic

	if accepting.calls != 1 {
		t.Errorf("Inspect() called %d times on the accepting inspector, want 1", accepting.calls)
	}
}

// candidateRejectingPassiveInspector never accepts a candidate; its Inspect
// panics so the test above fails loudly if Candidate is ever bypassed.
type candidateRejectingPassiveInspector struct{}

func (candidateRejectingPassiveInspector) Name() string                       { return "reject" }
func (candidateRejectingPassiveInspector) Candidate(dpi.CandidatePacket) bool { return false }
func (candidateRejectingPassiveInspector) Inspect([]byte) []dpi.HostnameFinding {
	panic("Inspect must not be called when Candidate is false")
}

// TestCapturerInspectPassiveStripsTCPLengthPrefix covers DNS-over-TCP: the
// 2-byte message-length prefix must be stripped before PassiveInspectors
// see the payload, so a real dpi.DNSAnswerInspector (which expects one bare
// DNS message) still finds the answer.
func TestCapturerInspectPassiveStripsTCPLengthPrefix(t *testing.T) {
	c := New(DefaultConfig())
	c.cfg.PassiveInspectors = dpi.DefaultPassiveInspectors()
	now := time.Now()

	msg := dnsResponse(t, "example.com", net.IPv4(93, 184, 216, 34))
	prefixed := append([]byte{byte(len(msg) >> 8), byte(len(msg))}, msg...)

	data := serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 53, DstPort: 51000, PSH: true, ACK: true},
		gopacket.Payload(prefixed))
	info := packetInfo{Proto: ProtoTCP, SrcPort: 53, DstPort: 51000, Bytes: uint64(len(data) - 14)}
	c.inspectPassive(data, info, layers.LinkTypeEthernet, now)

	if got, ok := c.hostnameCache.Get("93.184.216.34", now); !ok || got != "example.com" {
		t.Fatalf("HostnameCache Get() = %q, %v; want %q, true", got, ok, "example.com")
	}
}

// dnsResponse serializes a minimal DNS response naming ip for host, the same
// way dpi's own tests build DNS wire bytes.
func dnsResponse(t *testing.T, host string, ip net.IP) []byte {
	t.Helper()

	msg := &layers.DNS{QR: true}
	msg.Questions = append(msg.Questions, layers.DNSQuestion{
		Name: []byte(host), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
	})
	msg.Answers = append(msg.Answers, layers.DNSResourceRecord{
		Name: []byte(host), Type: layers.DNSTypeA, Class: layers.DNSClassIN, IP: ip,
	})

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, msg); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return buf.Bytes()
}

// tlsClientHelloRecord hand-encodes a minimal TLS 1.2 ClientHello record
// carrying a single server_name (SNI) extension, following the same
// approach as dpi/tls_test.go's buildClientHello.
func tlsClientHelloRecord(sni string) []byte {
	u16 := func(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }

	nameEntry := append([]byte{0x00}, u16(uint16(len(sni)))...)
	nameEntry = append(nameEntry, sni...)
	serverNameList := append(u16(uint16(len(nameEntry))), nameEntry...)
	extensions := append([]byte{0x00, 0x00}, u16(uint16(len(serverNameList)))...)
	extensions = append(extensions, serverNameList...)

	// A padding extension (RFC 7685, type 21), sized so the whole datagram
	// clears minPayloadDatagramLen regardless of how long sni is — real
	// ClientHellos are always this size or bigger once their real cipher
	// suite list and extension set are counted.
	const paddingLen = 200
	padding := append([]byte{0x00, 0x15}, u16(paddingLen)...)
	padding = append(padding, make([]byte, paddingLen)...)
	extensions = append(extensions, padding...)

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, u16(2)...)
	body = append(body, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, u16(uint16(len(extensions)))...)
	body = append(body, extensions...)

	bodyLen := len(body)
	handshake := append([]byte{0x01, byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen)}, body...)

	record := []byte{0x16, 0x03, 0x01}
	record = append(record, u16(uint16(len(handshake)))...)
	return append(record, handshake...)
}

// TestCapturerInspectSkipsHeaderOnlySegments is the regression test for the
// bug where Candidate gated on the captured frame's length: a bare SYN, even
// with a full set of TCP options, is under 120 bytes of real datagram, but a
// gate based on captured/frame length alone (rather than the datagram's own
// reported size) let it through anyway — permanently consuming the flow's
// one inspection attempt (see ByteCounter.NeedsHostnameInspection) before
// the actual ClientHello ever arrived.
func TestCapturerInspectSkipsHeaderOnlySegments(t *testing.T) {
	c := New(DefaultConfig())
	c.cfg.Inspectors = dpi.DefaultInspectors()
	now := time.Now()

	key := FlowKey{
		LocalAddr:  mustAddr(t, "192.168.1.10"),
		LocalPort:  51000,
		RemoteAddr: mustAddr(t, "140.82.112.3"),
		RemotePort: 443,
		Proto:      ProtoTCP,
	}
	ctr := c.record(key, now, 0, false)

	syn := serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51000, DstPort: 443, SYN: true, DataOffset: 15, Options: []layers.TCPOption{{
			OptionType: layers.TCPOptionKindTimestamps, OptionLength: 34,
			OptionData: bytes.Repeat([]byte{1}, 32),
		}}})
	synInfo := packetInfo{Proto: ProtoTCP, SrcPort: 51000, DstPort: 443, Bytes: uint64(len(syn) - 14)}
	c.inspect(syn, synInfo, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)

	if !ctr.NeedsHostnameInspection() {
		t.Fatal("a header-only SYN consumed the flow's one inspection attempt")
	}

	full := serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51000, DstPort: 443, PSH: true, ACK: true},
		gopacket.Payload(tlsClientHelloRecord("example.com")))
	fullInfo := packetInfo{Proto: ProtoTCP, SrcPort: 51000, DstPort: 443, Bytes: uint64(len(full) - 14)}
	c.inspect(full, fullInfo, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)

	if got := ctr.Hostname(); got != "example.com" {
		t.Fatalf("Hostname() = %q, want %q: the ClientHello following the SYN should still get inspected", got, "example.com")
	}
}

// TestCapturerInspectReassemblesASplitClientHello covers the case
// TestCapturerInspectSkipsHeaderOnlySegments does not: a ClientHello whose
// SNI extension lands in a second TCP segment, split at an arbitrary byte
// offset the way a large post-quantum key share pushes the record past one
// packet's worth of payload.
func TestCapturerInspectReassemblesASplitClientHello(t *testing.T) {
	c := New(DefaultConfig())
	c.cfg.Inspectors = dpi.DefaultInspectors()
	now := time.Now()

	key := FlowKey{
		LocalAddr:  mustAddr(t, "192.168.1.10"),
		LocalPort:  51000,
		RemoteAddr: mustAddr(t, "140.82.112.3"),
		RemotePort: 443,
		Proto:      ProtoTCP,
	}
	ctr := c.record(key, now, 0, false)

	full := tlsClientHelloRecord("split.example.com")
	// Split near the end: the first chunk alone must still clear Candidate's
	// datagram-length gate, and the second must not, to prove a continuation
	// packet is fed in regardless of size once a hello is already in progress.
	split := len(full) - 60
	const startSeq = 5000

	first := serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51000, DstPort: 443, Seq: startSeq, PSH: true, ACK: true},
		gopacket.Payload(full[:split]))
	firstInfo := packetInfo{Proto: ProtoTCP, SrcPort: 51000, DstPort: 443, Bytes: uint64(len(first) - 14)}
	c.inspect(first, firstInfo, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)

	if got := ctr.Hostname(); got != "" {
		t.Fatalf("Hostname() = %q after the first segment alone, want empty", got)
	}
	if !ctr.NeedsHostnameInspection() {
		t.Fatal("NeedsHostnameInspection() = false after only the first of two segments")
	}

	// The second segment is small enough on its own to fail Candidate's
	// length gate — proving continuation packets are fed in regardless once
	// a hello is already in progress.
	second := serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51000, DstPort: 443, Seq: startSeq + uint32(split), PSH: true, ACK: true},
		gopacket.Payload(full[split:]))
	secondInfo := packetInfo{Proto: ProtoTCP, SrcPort: 51000, DstPort: 443, Bytes: uint64(len(second) - 14)}
	c.inspect(second, secondInfo, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)

	if got := ctr.Hostname(); got != "split.example.com" {
		t.Fatalf("Hostname() = %q, want %q", got, "split.example.com")
	}
	if ctr.NeedsHostnameInspection() {
		t.Fatal("NeedsHostnameInspection() = true after reassembly completed")
	}
}

func TestCapturerInspectStopsRetryingAfterAMiss(t *testing.T) {
	c := New(DefaultConfig())
	now := time.Now()

	key := FlowKey{RemoteAddr: mustAddr(t, "140.82.112.3"), RemotePort: 443, Proto: ProtoTCP}
	ctr := c.record(key, now, 1000, false)

	insp := &fakeInspector{ok: false}
	c.cfg.Inspectors = []dpi.Inspector{insp}

	// A complete, well-formed record so the assembler hands it to insp on the
	// first packet — insp itself is the one reporting the miss.
	data := serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51000, DstPort: 443, PSH: true, ACK: true},
		gopacket.Payload(tlsClientHelloRecord("example.com")))
	info := packetInfo{Proto: ProtoTCP, DstPort: 443, Bytes: uint64(len(data) - 14)}
	c.inspect(data, info, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)
	c.inspect(data, info, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)

	if insp.calls != 1 {
		t.Errorf("Inspect() called %d times after a miss, want 1", insp.calls)
	}
	if ctr.Hostname() != "" {
		t.Errorf("ByteCounter.Hostname() = %q, want empty", ctr.Hostname())
	}
}

// TestCapturerInspectGivesUpAfterOneNonMatchingPayload covers the
// consequence of Candidate no longer being able to reject a flow cheaply by
// port alone (see dpi.TLSSNIInspector.Candidate): once a flow's first
// payload-bearing packet has been extracted and shown to none of the
// configured Inspectors, the flow's one-shot budget is spent right there —
// a genuine ClientHello is always a fresh connection's first payload, so a
// flow whose opening packet is plain HTTP (say) must not keep paying
// extraction cost on every later packet for the rest of its life.
func TestCapturerInspectGivesUpAfterOneNonMatchingPayload(t *testing.T) {
	c := New(DefaultConfig())
	c.cfg.Inspectors = dpi.DefaultInspectors()
	now := time.Now()

	key := FlowKey{
		LocalAddr:  mustAddr(t, "192.168.1.10"),
		LocalPort:  51000,
		RemoteAddr: mustAddr(t, "140.82.112.3"),
		RemotePort: 4317,
		Proto:      ProtoTCP,
	}
	ctr := c.record(key, now, 0, false)

	notTLS := serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51000, DstPort: 4317, PSH: true, ACK: true},
		gopacket.Payload(bytes.Repeat([]byte{0xAB}, 200)))
	notTLSInfo := packetInfo{Proto: ProtoTCP, SrcPort: 51000, DstPort: 4317, Bytes: uint64(len(notTLS) - 14)}
	c.inspect(notTLS, notTLSInfo, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)

	if ctr.NeedsHostnameInspection() {
		t.Fatal("NeedsHostnameInspection() = true after the flow's opening payload was examined and matched nothing")
	}

	full := serialize(t, ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51000, DstPort: 4317, PSH: true, ACK: true},
		gopacket.Payload(tlsClientHelloRecord("example.com")))
	fullInfo := packetInfo{Proto: ProtoTCP, SrcPort: 51000, DstPort: 4317, Bytes: uint64(len(full) - 14)}
	c.inspect(full, fullInfo, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)

	if got := ctr.Hostname(); got != "" {
		t.Fatalf("Hostname() = %q, want empty: a ClientHello arriving after the flow's opening packet must not be re-examined", got)
	}
}

func TestCapturerInspectNilInspectorsIsNoop(t *testing.T) {
	c := New(DefaultConfig())
	c.cfg.Inspectors = nil
	now := time.Now()

	key := FlowKey{RemoteAddr: mustAddr(t, "140.82.112.3"), RemotePort: 443, Proto: ProtoTCP}
	ctr := c.record(key, now, 1000, false)

	info := packetInfo{Proto: ProtoTCP, DstPort: 443}
	c.inspect([]byte("clienthello"), info, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)

	if ctr.Hostname() != "" {
		t.Errorf("ByteCounter.Hostname() = %q, want empty with no inspectors configured", ctr.Hostname())
	}
}

func TestListInterfaces(t *testing.T) {
	names, err := ListInterfaces()
	if err != nil {
		// libpcap enumeration needs elevated privileges on some hosts; nothing
		// to assert against there.
		t.Skipf("ListInterfaces() error = %v", err)
	}
	if names == nil {
		t.Fatal("ListInterfaces() = nil slice, want a non-nil slice")
	}
}

func TestDefaultInterfaceNamesARealDevice(t *testing.T) {
	name, err := DefaultInterface()
	if err != nil {
		// No default route and no capturable device: nothing to assert on a
		// machine that is offline or denies libpcap to a non-root test.
		t.Skipf("no default interface available: %v", err)
	}
	if _, err := net.InterfaceByName(name); err != nil {
		t.Fatalf("DefaultInterface() = %q, which the OS does not know: %v", name, err)
	}
}

// TestCapturerRunStopsOnContextCancel needs a live handle, so it only runs as
// root and outside -short.
func TestCapturerRunStopsOnContextCancel(t *testing.T) {
	if testing.Short() {
		t.Skip("opens a live pcap handle")
	}
	if os.Geteuid() != 0 {
		t.Skip("opening a pcap handle needs root")
	}

	iface, err := DefaultInterface()
	if err != nil {
		t.Skipf("no default interface: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Interface = iface

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- New(cfg).Run(ctx) }()

	// Give the handle time to open before pulling the rug out, so the test
	// exercises the read loop rather than the setup path.
	time.AfterFunc(200*time.Millisecond, cancel)

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return within 5s of cancellation")
	}
}

func TestCapturerEvictDropsStaleFlows(t *testing.T) {
	c := New(DefaultConfig())
	now := time.Now()

	fresh := FlowKey{LocalAddr: mustAddr(t, "10.0.0.1"), LocalPort: 1, Proto: ProtoTCP}
	stale := FlowKey{LocalAddr: mustAddr(t, "10.0.0.1"), LocalPort: 2, Proto: ProtoTCP}

	c.record(fresh, now, 100, true)
	c.record(stale, now.Add(-time.Minute), 100, true)

	if n := c.Evict(now.Add(-30*time.Second), nil); n != 1 {
		t.Fatalf("Evict() removed %d flows, want 1", n)
	}
	if _, ok := c.flows[stale]; ok {
		t.Error("stale flow survived Evict()")
	}
	if _, ok := c.flows[fresh]; !ok {
		t.Error("Evict() removed a flow that was still active")
	}

	// A second pass with the same cutoff has nothing left to do.
	if n := c.Evict(now.Add(-30*time.Second), nil); n != 0 {
		t.Errorf("second Evict() removed %d flows, want 0", n)
	}
}

func TestCapturerEvictSparesKeptFlows(t *testing.T) {
	c := New(DefaultConfig())
	now := time.Now()

	kept := FlowKey{LocalAddr: mustAddr(t, "10.0.0.1"), LocalPort: 1, Proto: ProtoTCP}
	stale := FlowKey{LocalAddr: mustAddr(t, "10.0.0.1"), LocalPort: 2, Proto: ProtoTCP}

	// Both flows are equally stale by LastSeen; only keep should survive.
	c.record(kept, now.Add(-time.Minute), 100, true)
	c.record(stale, now.Add(-time.Minute), 100, true)

	keep := map[FlowKey]struct{}{kept: {}}
	if n := c.Evict(now.Add(-30*time.Second), keep); n != 1 {
		t.Fatalf("Evict() removed %d flows, want 1", n)
	}
	if _, ok := c.flows[stale]; ok {
		t.Error("stale flow survived Evict()")
	}
	if _, ok := c.flows[kept]; !ok {
		t.Error("Evict() removed a flow it was told to keep")
	}
}

func TestCapturerEvictConcurrentWithRecord(t *testing.T) {
	// Evict walks the map while holding the write lock and calls into each
	// counter's own lock; recording concurrently must not deadlock or race.
	c := New(DefaultConfig())
	now := time.Now()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := range 200 {
			key := FlowKey{LocalAddr: mustAddr(t, "10.0.0.1"), LocalPort: uint16(i % 16), Proto: ProtoUDP}
			c.record(key, now, 1, true)
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			c.Evict(now.Add(time.Second), nil)
		}
	}()

	wg.Wait()
}
