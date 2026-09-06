package capture

import (
	"net/netip"
	"testing"
	"time"
)

func TestByteCounterTotalsAreMonotonic(t *testing.T) {
	var c ByteCounter
	now := time.Now().Truncate(time.Second)

	c.Add(now, 100, true)
	c.Add(now.Add(time.Second), 50, false)
	// Well beyond the rate window: totals must survive, rates must not.
	c.Add(now.Add(time.Minute), 25, true)

	in, out := c.Totals()
	if in != 125 || out != 50 {
		t.Fatalf("totals = (%d, %d), want (125, 50)", in, out)
	}
}

func TestByteCounterRateOverWindow(t *testing.T) {
	var c ByteCounter
	now := time.Now().Truncate(time.Second)

	// One second's worth of traffic, read back within the window.
	c.Add(now, 5000, true)
	c.Add(now, 1000, false)

	in, out := c.Rates(now)
	wantIn := 5000.0 / rateWindow.Seconds()
	wantOut := 1000.0 / rateWindow.Seconds()
	if in != wantIn || out != wantOut {
		t.Fatalf("rates = (%.1f, %.1f), want (%.1f, %.1f)", in, out, wantIn, wantOut)
	}
}

func TestByteCounterRateDecaysToZero(t *testing.T) {
	var c ByteCounter
	now := time.Now().Truncate(time.Second)

	c.Add(now, 5000, true)

	// Once the whole window has rolled past, a silent flow reads as zero
	// rather than holding its last rate.
	in, out := c.Rates(now.Add(rateWindow + time.Second))
	if in != 0 || out != 0 {
		t.Fatalf("rates after idle = (%.1f, %.1f), want (0, 0)", in, out)
	}
}

func TestByteCounterRingWrapsWithoutLosingRecentTraffic(t *testing.T) {
	var c ByteCounter
	now := time.Now().Truncate(time.Second)

	// Traffic every second for longer than the ring: only the last
	// rateBuckets seconds should count towards the rate.
	for i := range 20 {
		c.Add(now.Add(time.Duration(i)*time.Second), 1000, true)
	}

	in, _ := c.Rates(now.Add(19 * time.Second))
	want := float64(rateBuckets*1000) / rateWindow.Seconds()
	if in != want {
		t.Fatalf("rate = %.1f, want %.1f", in, want)
	}

	if total, _ := c.Totals(); total != 20000 {
		t.Fatalf("total = %d, want 20000", total)
	}
}

func TestRateWindowMatchesBucketCount(t *testing.T) {
	// The rate maths divides the whole ring by rateWindow, so the two
	// constants must stay in step.
	if time.Duration(rateBuckets)*time.Second != rateWindow {
		t.Fatalf("rateBuckets (%d) does not cover rateWindow (%s)", rateBuckets, rateWindow)
	}
}

func TestProtoString(t *testing.T) {
	tests := []struct {
		name string
		p    Proto
		want string
	}{
		{name: "tcp", p: ProtoTCP, want: "tcp"},
		{name: "udp", p: ProtoUDP, want: "udp"},
		{name: "icmp", p: ProtoICMP, want: "icmp"},
		{name: "arp", p: ProtoARP, want: "arp"},
		{name: "unrecognised value", p: Proto(255), want: "?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("Proto(%d).String() = %q, want %q", tt.p, got, tt.want)
			}
		})
	}
}

func TestFlowKeyString(t *testing.T) {
	key := FlowKey{
		LocalAddr:  mustAddr(t, "192.168.1.10"),
		LocalPort:  51000,
		RemoteAddr: mustAddr(t, "140.82.112.3"),
		RemotePort: 443,
		Proto:      ProtoTCP,
	}

	want := "tcp 192.168.1.10:51000 -> 140.82.112.3:443"
	if got := key.String(); got != want {
		t.Errorf("FlowKey.String() = %q, want %q", got, want)
	}
}

// mustAddr parses a literal IP address for tests, failing loudly on a typo.
func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("netip.ParseAddr(%q): %v", s, err)
	}
	return addr
}

func TestNormalise(t *testing.T) {
	local4 := mustAddr(t, "192.168.1.10")
	local6 := mustAddr(t, "2001:db8::1")
	loop4 := mustAddr(t, "127.0.0.1")
	remote4 := mustAddr(t, "140.82.112.3")
	remote6 := mustAddr(t, "2606:4700::1111")

	locals := map[netip.Addr]struct{}{
		local4: {},
		local6: {},
		loop4:  {},
	}
	isLocal := func(a netip.Addr) bool {
		_, found := locals[a]
		return found
	}

	tests := []struct {
		name         string
		src, dst     netip.Addr
		sport, dport uint16
		proto        Proto
		wantKey      FlowKey
		wantInbound  bool
		wantOK       bool
	}{
		{
			name: "outbound v4 puts our address in the local fields",
			src:  local4, dst: remote4, sport: 51000, dport: 443, proto: ProtoTCP,
			wantKey: FlowKey{LocalAddr: local4, LocalPort: 51000, RemoteAddr: remote4, RemotePort: 443, Proto: ProtoTCP, Iface: "eth0"},
			wantOK:  true,
		},
		{
			name: "inbound v4 folds onto the same key as the outbound half",
			src:  remote4, dst: local4, sport: 443, dport: 51000, proto: ProtoTCP,
			wantKey:     FlowKey{LocalAddr: local4, LocalPort: 51000, RemoteAddr: remote4, RemotePort: 443, Proto: ProtoTCP, Iface: "eth0"},
			wantInbound: true,
			wantOK:      true,
		},
		{
			name: "outbound v6 udp",
			src:  local6, dst: remote6, sport: 5353, dport: 53, proto: ProtoUDP,
			wantKey: FlowKey{LocalAddr: local6, LocalPort: 5353, RemoteAddr: remote6, RemotePort: 53, Proto: ProtoUDP, Iface: "eth0"},
			wantOK:  true,
		},
		{
			name: "inbound v6 udp",
			src:  remote6, dst: local6, sport: 53, dport: 5353, proto: ProtoUDP,
			wantKey:     FlowKey{LocalAddr: local6, LocalPort: 5353, RemoteAddr: remote6, RemotePort: 53, Proto: ProtoUDP, Iface: "eth0"},
			wantInbound: true,
			wantOK:      true,
		},
		{
			// Both ends are ours, so the source side wins and each endpoint
			// gets its own row rather than the bytes being counted twice.
			name: "loopback attributes to the sending side",
			src:  loop4, dst: loop4, sport: 51000, dport: 8080, proto: ProtoTCP,
			wantKey: FlowKey{LocalAddr: loop4, LocalPort: 51000, RemoteAddr: loop4, RemotePort: 8080, Proto: ProtoTCP, Iface: "eth0"},
			wantOK:  true,
		},
		{
			name: "neither end local is dropped",
			src:  remote4, dst: mustAddr(t, "1.1.1.1"), sport: 1234, dport: 80, proto: ProtoTCP,
			wantOK: false,
		},
		{
			name: "multicast destination from a remote sender is dropped",
			src:  remote4, dst: mustAddr(t, "224.0.0.251"), sport: 5353, dport: 5353, proto: ProtoUDP,
			wantOK: false,
		},
		{
			name: "multicast destination from us is still ours",
			src:  local4, dst: mustAddr(t, "224.0.0.251"), sport: 5353, dport: 5353, proto: ProtoUDP,
			wantKey: FlowKey{LocalAddr: local4, LocalPort: 5353, RemoteAddr: mustAddr(t, "224.0.0.251"), RemotePort: 5353, Proto: ProtoUDP, Iface: "eth0"},
			wantOK:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, inbound, ok := normalise(tt.src, tt.dst, tt.sport, tt.dport, tt.proto, "eth0", isLocal)
			if ok != tt.wantOK {
				t.Fatalf("normalise() ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if key != tt.wantKey {
				t.Errorf("normalise() key = %v, want %v", key, tt.wantKey)
			}
			if inbound != tt.wantInbound {
				t.Errorf("normalise() inbound = %v, want %v", inbound, tt.wantInbound)
			}
		})
	}
}

func TestNormaliseIsDirectionSymmetric(t *testing.T) {
	local := mustAddr(t, "10.0.0.5")
	remote := mustAddr(t, "93.184.216.34")
	isLocal := func(a netip.Addr) bool { return a == local }

	out, outInbound, ok := normalise(local, remote, 40000, 80, ProtoTCP, "eth0", isLocal)
	if !ok {
		t.Fatal("normalise() dropped an outbound packet")
	}
	in, inInbound, ok := normalise(remote, local, 80, 40000, ProtoTCP, "eth0", isLocal)
	if !ok {
		t.Fatal("normalise() dropped an inbound packet")
	}

	if out != in {
		t.Fatalf("directions produced different keys: %v vs %v", out, in)
	}
	if outInbound || !inInbound {
		t.Fatalf("direction flags = (%v, %v), want (false, true)", outInbound, inInbound)
	}
}

// TestFlowKeyIfaceDifferentiatesOtherwiseIdenticalFlows pins down the reason
// FlowKey carries Iface at all: two flows with an identical 5-tuple, seen on
// different interfaces (the primary interface and loopback, say), must not
// collide into one entry.
func TestFlowKeyIfaceDifferentiatesOtherwiseIdenticalFlows(t *testing.T) {
	local := mustAddr(t, "127.0.0.1")
	remote := mustAddr(t, "127.0.0.1")
	isLocal := func(a netip.Addr) bool { return a == local }

	primary, _, ok := normalise(local, remote, 51000, 8080, ProtoTCP, "en0", isLocal)
	if !ok {
		t.Fatal("normalise() dropped a packet it should have kept")
	}
	loopback, _, ok := normalise(local, remote, 51000, 8080, ProtoTCP, "lo0", isLocal)
	if !ok {
		t.Fatal("normalise() dropped a packet it should have kept")
	}

	if primary == loopback {
		t.Fatalf("keys on different interfaces collided: %+v", primary)
	}
	if primary.Iface != "en0" || loopback.Iface != "lo0" {
		t.Fatalf("Iface = (%q, %q), want (\"en0\", \"lo0\")", primary.Iface, loopback.Iface)
	}
}

func TestByteCounterHostnameSetOnce(t *testing.T) {
	c := &ByteCounter{}
	c.SetHostname("first.example.com")
	c.SetHostname("second.example.com")

	if got := c.Hostname(); got != "first.example.com" {
		t.Errorf("Hostname() = %q, want %q (first write wins)", got, "first.example.com")
	}
}

func TestByteCounterNeedsHostnameInspection(t *testing.T) {
	t.Run("true before anything happens", func(t *testing.T) {
		c := &ByteCounter{}
		if !c.NeedsHostnameInspection() {
			t.Error("NeedsHostnameInspection() = false for a fresh counter")
		}
	})

	t.Run("false once a hostname is set", func(t *testing.T) {
		c := &ByteCounter{}
		c.SetHostname("example.com")
		if c.NeedsHostnameInspection() {
			t.Error("NeedsHostnameInspection() = true after SetHostname")
		}
	})

	t.Run("false once an attempt is marked, even with no hostname", func(t *testing.T) {
		c := &ByteCounter{}
		c.MarkHostnameAttempted()
		if c.NeedsHostnameInspection() {
			t.Error("NeedsHostnameInspection() = true after MarkHostnameAttempted")
		}
	})
}

func TestByteCounterHelloInProgress(t *testing.T) {
	c := &ByteCounter{}
	if c.HelloInProgress() {
		t.Error("HelloInProgress() = true for a fresh counter")
	}

	// A single segment already completing a record still counts as "in
	// progress" having been touched at all — callers only consult this
	// before NeedsHostnameInspection has gone false, so it does not matter
	// that reassembly finished on the first call.
	c.AddHelloSegment("tls-sni", 1000, []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x00})
	if !c.HelloInProgress() {
		t.Error("HelloInProgress() = false after AddHelloSegment")
	}
	if got := c.HelloInspector(); got != "tls-sni" {
		t.Errorf("HelloInspector() = %q, want %q", got, "tls-sni")
	}
}

func TestByteCounterAddHelloSegmentJoinsAcrossCalls(t *testing.T) {
	c := &ByteCounter{}

	first := []byte{0x16, 0x03, 0x01, 0x00, 0x02}
	if ready, done := c.AddHelloSegment("tls-sni", 1000, first); ready != nil || done {
		t.Fatalf("AddHelloSegment(first) = ready %v, done=%v; want nil, false", ready, done)
	}

	second := []byte{0xAA, 0xBB}
	ready, done := c.AddHelloSegment("tls-sni", 1000+uint32(len(first)), second)
	want := append(append([]byte{}, first...), second...)
	if !done || string(ready) != string(want) {
		t.Fatalf("AddHelloSegment(second) = ready %v, done=%v; want %v, true", ready, done, want)
	}
}

func TestByteCounterAddHelloSegmentKeepsFirstInspector(t *testing.T) {
	c := &ByteCounter{}

	c.AddHelloSegment("tls-sni", 1000, []byte{0x16})
	// A later call naming a different inspector must not steal or reset the
	// reassembly already under way for the first one.
	c.AddHelloSegment("quic-sni", 1001, []byte{0x17})
	if got := c.HelloInspector(); got != "tls-sni" {
		t.Errorf("HelloInspector() = %q, want %q (the inspector that started reassembly)", got, "tls-sni")
	}
}
