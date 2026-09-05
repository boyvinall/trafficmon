//go:build linux

package procinfo

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestListPIDs is a smoke test: our own PID must be among the ones read from
// /proc.
func TestListPIDs(t *testing.T) {
	pids, err := ListPIDs()
	if err != nil {
		t.Fatalf("ListPIDs: %v", err)
	}
	if len(pids) == 0 {
		t.Fatal("ListPIDs returned no PIDs")
	}

	self := int32(os.Getpid())
	for _, pid := range pids {
		if pid == self {
			return
		}
	}
	t.Fatalf("own pid %d not found among %d pids", self, len(pids))
}

func TestProcessName(t *testing.T) {
	name, err := ProcessName(int32(os.Getpid()))
	if err != nil {
		t.Fatalf("ProcessName: %v", err)
	}
	if name == "" {
		t.Fatal("ProcessName returned an empty name")
	}
	t.Logf("own process name: %q", name)

	// The test binary's argv[0] is a path (go test builds it under a temp
	// directory), so a correct implementation must report the basename, not
	// the whole path.
	if name != filepath.Base(name) {
		t.Errorf("ProcessName(own pid) = %q, want a bare name with no directory component", name)
	}
}

// TestProcessNameArgv0 asserts that ProcessName prefers argv[0] over the
// kernel's comm, since comm is the basename of the executable *path* and can
// differ sharply from the name a process presents.
func TestProcessNameArgv0(t *testing.T) {
	name, ok := argv0(int32(os.Getpid()))
	if !ok {
		t.Fatal("argv0(own pid) failed")
	}
	if name == "" {
		t.Fatal("argv0(own pid) returned an empty string")
	}
	t.Logf("own argv[0]: %q", name)

	got, err := ProcessName(int32(os.Getpid()))
	if err != nil {
		t.Fatalf("ProcessName: %v", err)
	}
	if want := filepath.Base(name); got != want {
		t.Errorf("ProcessName(own pid) = %q, want basename of argv[0] %q", got, want)
	}
}

func closeLater(t *testing.T, c interface{ Close() error }) {
	t.Helper()
	t.Cleanup(func() { _ = c.Close() })
}

func findSocket(socks []Socket, port uint16, proto string) (Socket, bool) {
	for _, s := range socks {
		if s.LocalPort == port && s.Proto == proto {
			return s, true
		}
	}
	return Socket{}, false
}

func portOf(t *testing.T, addr string) uint16 {
	t.Helper()
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		t.Fatalf("parse %q: %v", addr, err)
	}
	return ap.Port()
}

// TestSocketsForPIDListening opens a real TCP listener and a real UDP socket
// and checks that both come back with the right protocol and local address.
func TestSocketsForPIDListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	closeLater(t, ln)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	closeLater(t, pc)

	tcpPort := portOf(t, ln.Addr().String())
	udpPort := portOf(t, pc.LocalAddr().String())

	socks, err := SocketsForPID(int32(os.Getpid()))
	if err != nil {
		t.Fatalf("SocketsForPID: %v", err)
	}

	s, ok := findSocket(socks, tcpPort, "tcp")
	if !ok {
		t.Fatalf("listening tcp port %d not found in %d sockets", tcpPort, len(socks))
	}
	if s.LocalAddr.String() != "127.0.0.1" {
		t.Errorf("tcp listener local addr = %q, want 127.0.0.1", s.LocalAddr)
	}
	if s.RemotePort != 0 {
		t.Errorf("tcp listener remote port = %d, want 0", s.RemotePort)
	}
	if s.State != "LISTEN" {
		t.Errorf("tcp listener state = %q, want LISTEN", s.State)
	}
	if s.PID != int32(os.Getpid()) {
		t.Errorf("socket PID = %d, want %d", s.PID, os.Getpid())
	}

	u, ok := findSocket(socks, udpPort, "udp")
	if !ok {
		t.Fatalf("udp port %d not found in %d sockets", udpPort, len(socks))
	}
	if u.LocalAddr.String() != "127.0.0.1" {
		t.Errorf("udp local addr = %q, want 127.0.0.1", u.LocalAddr)
	}
	if u.State != "" {
		t.Errorf("udp state = %q, want empty", u.State)
	}
}

// TestSocketsForPIDEstablished checks the connected case, where both ends
// must decode correctly: the client socket's remote port has to be the
// listener's port, and vice versa on the accepted socket.
func TestSocketsForPIDEstablished(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr string
		want string
	}{
		{"ipv4", "127.0.0.1:0", "127.0.0.1"},
		{"ipv6", "[::1]:0", "::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", tc.addr)
			if err != nil {
				// A machine may have IPv6 disabled entirely.
				t.Skipf("listen %s: %v", tc.addr, err)
			}
			closeLater(t, ln)

			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial %s: %v", ln.Addr(), err)
			}
			closeLater(t, conn)

			server, err := ln.Accept()
			if err != nil {
				t.Fatalf("accept: %v", err)
			}
			closeLater(t, server)

			clientPort := portOf(t, conn.LocalAddr().String())
			serverPort := portOf(t, ln.Addr().String())

			socks, err := SocketsForPID(int32(os.Getpid()))
			if err != nil {
				t.Fatalf("SocketsForPID: %v", err)
			}

			client, ok := findSocket(socks, clientPort, "tcp")
			if !ok {
				t.Fatalf("client port %d not found in %d sockets", clientPort, len(socks))
			}
			if client.RemotePort != serverPort {
				t.Errorf("client remote port = %d, want %d", client.RemotePort, serverPort)
			}
			if got := client.LocalAddr.String(); got != tc.want {
				t.Errorf("client local addr = %q, want %q", got, tc.want)
			}
			if got := client.RemoteAddr.String(); got != tc.want {
				t.Errorf("client remote addr = %q, want %q", got, tc.want)
			}

			var accepted bool
			for _, s := range socks {
				if s.Proto == "tcp" && s.LocalPort == serverPort && s.RemotePort == clientPort {
					accepted = true
					if got := s.RemoteAddr.String(); got != tc.want {
						t.Errorf("accepted remote addr = %q, want %q", got, tc.want)
					}
				}
			}
			if !accepted {
				t.Errorf("no accepted socket %d -> %d found", serverPort, clientPort)
			}
		})
	}
}

// TestSocketsForPIDMissing checks that an unused PID is reported as an error
// rather than panicking or returning junk, since the poller walks PIDs that
// can disappear underneath it.
func TestSocketsForPIDMissing(t *testing.T) {
	pids, err := ListPIDs()
	if err != nil {
		t.Fatalf("ListPIDs: %v", err)
	}
	live := make(map[int32]bool, len(pids))
	for _, pid := range pids {
		live[pid] = true
	}

	var dead int32
	for candidate := int32(99990); candidate > 1; candidate-- {
		if !live[candidate] {
			dead = candidate
			break
		}
	}
	if dead == 0 {
		t.Skip("no unused PID available")
	}

	socks, err := SocketsForPID(dead)
	if err == nil && len(socks) != 0 {
		t.Fatalf("SocketsForPID(%d) returned %d sockets for a dead pid", dead, len(socks))
	}
	t.Logf("SocketsForPID(%d) = %d sockets, err %v", dead, len(socks), err)
}

// TestPollerPoll is the whole join in miniature: a port we opened ourselves
// must map back to our own PID and process name.
func TestPollerPoll(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closeLater(t, ln)

	port := portOf(t, ln.Addr().String())

	p := NewPoller()
	if err := p.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}

	proc, ok := p.Lookup(port, "tcp")
	if !ok {
		t.Fatalf("port %d not found in port map of %d entries", port, len(p.Snapshot()))
	}
	if proc.PID != int32(os.Getpid()) {
		t.Errorf("port %d owned by pid %d, want %d", port, proc.PID, os.Getpid())
	}
	if proc.Name == "" || proc.Name == "?" {
		t.Errorf("port %d owner name = %q", port, proc.Name)
	}

	if snap := p.Snapshot(); snap[port] != proc {
		t.Errorf("Snapshot()[%d] = %+v, want %+v", port, snap[port], proc)
	}
}

func TestParseHexAddrPort(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantAddr string
		wantPort uint16
		wantErr  bool
	}{
		{"ipv4 loopback port 80", "0100007F:0050", "127.0.0.1", 80, false},
		{"ipv4 zero", "00000000:0000", "0.0.0.0", 0, false},
		{"ipv6 loopback", "00000000000000000000000001000000:0050", "::1", 80, false},
		{"malformed, no colon", "0100007F", "", 0, true},
		{"malformed hex", "ZZZZZZZZ:0050", "", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, port, err := parseHexAddrPort(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseHexAddrPort(%q) = %v, %v, want error", tc.in, addr, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseHexAddrPort(%q) error = %v", tc.in, err)
			}
			if addr.String() != tc.wantAddr || port != tc.wantPort {
				t.Errorf("parseHexAddrPort(%q) = %v, %v, want %v, %v", tc.in, addr, port, tc.wantAddr, tc.wantPort)
			}
		})
	}
}

func TestParseProcNetFile(t *testing.T) {
	const sample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0050 0200007F:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 20 4 30 10 -1
   2: not a valid row at all
`
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	if err := os.WriteFile(path, []byte(sample), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	out := make(map[uint64]procNetEntry)
	if err := parseProcNetFile(path, "tcp", out); err != nil {
		t.Fatalf("parseProcNetFile: %v", err)
	}

	listener, ok := out[12345]
	if !ok {
		t.Fatalf("inode 12345 not found in %v", out)
	}
	if listener.localPort != 8080 || listener.state != "LISTEN" {
		t.Errorf("listener entry = %+v, want localPort 8080, state LISTEN", listener)
	}

	established, ok := out[12346]
	if !ok {
		t.Fatalf("inode 12346 not found in %v", out)
	}
	if established.localPort != 80 || established.remotePort != 40000 || established.state != "ESTABLISHED" {
		t.Errorf("established entry = %+v, want localPort 80, remotePort 40000, state ESTABLISHED", established)
	}

	if len(out) != 2 {
		t.Errorf("parseProcNetFile parsed %d entries, want 2 (malformed row must be skipped)", len(out))
	}
}

func TestParseProcNetFileMissing(t *testing.T) {
	out := make(map[uint64]procNetEntry)
	if err := parseProcNetFile(filepath.Join(t.TempDir(), "nope"), "tcp", out); err != nil {
		t.Errorf("parseProcNetFile(missing file) error = %v, want nil", err)
	}
	if len(out) != 0 {
		t.Errorf("parseProcNetFile(missing file) populated %d entries, want 0", len(out))
	}
}

// TestTCPStateName covers every hex state value SocketsForPID can hand it,
// per include/net/tcp_states.h, plus an unrecognised value.
func TestTCPStateName(t *testing.T) {
	tests := []struct {
		name  string
		state int
		want  string
	}{
		{"established", 0x01, "ESTABLISHED"},
		{"syn sent", 0x02, "SYN_SENT"},
		{"syn recv", 0x03, "SYN_RECV"},
		{"fin wait1", 0x04, "FIN_WAIT1"},
		{"fin wait2", 0x05, "FIN_WAIT2"},
		{"time wait", 0x06, "TIME_WAIT"},
		{"close", 0x07, "CLOSE"},
		{"close wait", 0x08, "CLOSE_WAIT"},
		{"last ack", 0x09, "LAST_ACK"},
		{"listen", 0x0A, "LISTEN"},
		{"closing", 0x0B, "CLOSING"},
		{"new syn recv, unrecognised", 0x0C, ""},
		{"unrecognised value", 0x99, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tcpStateName(tc.state); got != tc.want {
				t.Errorf("tcpStateName(%d) = %q, want %q", tc.state, got, tc.want)
			}
		})
	}
}

// TestReadProcNetLive is a smoke test against the real /proc/net files: it
// only checks that reading them does not error, since their contents are not
// controllable from a test.
func TestReadProcNetLive(t *testing.T) {
	if _, err := readProcNet(); err != nil {
		t.Fatalf("readProcNet: %v", err)
	}
}

func TestArgv0MissingPID(t *testing.T) {
	if _, ok := argv0(1 << 30); ok {
		t.Error("argv0(implausible pid) = ok, want false")
	}
}

func TestParseHexAddrPortRoundTripsHex(t *testing.T) {
	// Guard against silently accepting an odd-length hex string as if it were
	// a valid 4- or 16-byte address.
	if _, _, err := parseHexAddrPort(strings.Repeat("A", 5) + ":0050"); err == nil {
		t.Error("parseHexAddrPort(odd-length hex) = nil error, want error")
	}
}
