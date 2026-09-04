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

func (f *fakeInspector) Inspect([]byte, layers.LinkType) (string, bool) {
	f.calls++
	return f.hostname, f.ok
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

	info := packetInfo{Proto: ProtoTCP, SrcPort: 51000, DstPort: 443}
	c.inspect([]byte("clienthello"), info, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)

	if got := ctr.Hostname(); got != "example.com" {
		t.Fatalf("ByteCounter.Hostname() = %q, want %q", got, "example.com")
	}
	if got, ok := c.hostnameCache.Get(key.RemoteAddr.String(), now); !ok || got != "example.com" {
		t.Fatalf("HostnameCache Get() = %q, %v; want %q, true", got, ok, "example.com")
	}

	// A second packet on the same flow must not re-invoke the inspector: the
	// hostname is already known.
	c.inspect([]byte("more data"), info, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)
	if insp.calls != 1 {
		t.Errorf("Inspect() called %d times, want 1", insp.calls)
	}
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
	// clears minClientHelloDatagramLen regardless of how long sni is — real
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

func TestCapturerInspectStopsRetryingAfterAMiss(t *testing.T) {
	c := New(DefaultConfig())
	now := time.Now()

	key := FlowKey{RemoteAddr: mustAddr(t, "140.82.112.3"), RemotePort: 443, Proto: ProtoTCP}
	ctr := c.record(key, now, 1000, false)

	insp := &fakeInspector{ok: false}
	c.cfg.Inspectors = []dpi.Inspector{insp}

	info := packetInfo{Proto: ProtoTCP, DstPort: 443}
	c.inspect([]byte("not tls"), info, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)
	c.inspect([]byte("still not tls"), info, false, layers.LinkTypeEthernet, key.RemoteAddr, ctr, now)

	if insp.calls != 1 {
		t.Errorf("Inspect() called %d times after a miss, want 1", insp.calls)
	}
	if ctr.Hostname() != "" {
		t.Errorf("ByteCounter.Hostname() = %q, want empty", ctr.Hostname())
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

	if n := c.Evict(now.Add(-30 * time.Second)); n != 1 {
		t.Fatalf("Evict() removed %d flows, want 1", n)
	}
	if _, ok := c.flows[stale]; ok {
		t.Error("stale flow survived Evict()")
	}
	if _, ok := c.flows[fresh]; !ok {
		t.Error("Evict() removed a flow that was still active")
	}

	// A second pass with the same cutoff has nothing left to do.
	if n := c.Evict(now.Add(-30 * time.Second)); n != 0 {
		t.Errorf("second Evict() removed %d flows, want 0", n)
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
			c.Evict(now.Add(time.Second))
		}
	}()

	wg.Wait()
}
