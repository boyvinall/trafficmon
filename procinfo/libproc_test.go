//go:build darwin

package procinfo

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// TestListPIDs is a smoke test for the cgo layer: if the libproc bindings link
// and the struct sizes are right, our own PID is in the list.
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
// kernel's p_comm, since p_comm is the basename of the executable *path* and
// can differ sharply from the name a process presents (self-updating apps
// commonly exec a version- or hash-named binary while keeping argv[0]
// friendly and stable).
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

// closeLater closes c when the test finishes. The error is deliberately
// dropped: a test teardown has nothing useful to do with it.
func closeLater(t *testing.T, c io.Closer) {
	t.Helper()
	t.Cleanup(func() { _ = c.Close() })
}

// findSocket returns the first socket in socks matching port and proto.
func findSocket(socks []Socket, port uint16, proto string) (Socket, bool) {
	for _, s := range socks {
		if s.LocalPort == port && s.Proto == proto {
			return s, true
		}
	}
	return Socket{}, false
}

// portOf extracts the port from a "host:port" address string.
func portOf(t *testing.T, addr string) uint16 {
	t.Helper()
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		t.Fatalf("parse %q: %v", addr, err)
	}
	return ap.Port()
}

// TestSocketsForPIDListening opens a real TCP listener and a real UDP socket and
// checks that both come back with the right protocol and local address. This is
// the end-to-end proof that the socket_fdinfo union decoding is correct: the
// ports are known independently, so a struct layout mistake cannot pass.
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
}

// TestSocketsForPIDEstablished checks the connected case, where both ends of the
// in_sockinfo address pair must decode: the client socket's remote port has to
// be the listener's port, and vice versa on the accepted socket.
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

			// The accepted socket shares the listener's local port, so look for
			// the one that has the client as its peer.
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
// rather than panicking or returning junk, since the poller walks PIDs that can
// disappear underneath it.
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

// TestPollerPoll is the whole join in miniature: a port we opened ourselves must
// map back to our own PID and process name.
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

// TestProtoName covers the kind/protocol combinations SocketsForPID can hand
// it: a TCP-kind socket, an IN-kind socket carrying either protocol number,
// and an unrecognised protocol. sockInfoTCP/ipprotoTCP/ipprotoUDP are the
// plain-int mirrors of the C constants, defined alongside protoName so this
// test does not need to import "C" itself.
func TestProtoName(t *testing.T) {
	tests := []struct {
		name     string
		kind     int
		protocol int
		want     string
	}{
		{"tcp kind wins regardless of protocol", sockInfoTCP, ipprotoUDP, "tcp"},
		{"in kind, tcp protocol", sockInfoIn, ipprotoTCP, "tcp"},
		{"in kind, udp protocol", sockInfoIn, ipprotoUDP, "udp"},
		{"in kind, unknown protocol", sockInfoIn, -1, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := protoName(tc.kind, tc.protocol); got != tc.want {
				t.Errorf("protoName(%v, %v) = %q, want %q", tc.kind, tc.protocol, got, tc.want)
			}
		})
	}
}

// TestTCPStateName covers every TSI_S_* state SocketsForPID can hand it, plus
// the -1 sentinel mn_read_sock_addrs uses for a socket with no state (UDP)
// and an unrecognised value, both of which fall back to "" rather than a
// bare kernel constant nobody would recognise.
func TestTCPStateName(t *testing.T) {
	tests := []struct {
		name  string
		state int
		want  string
	}{
		{"closed", tsiClosed, "CLOSED"},
		{"listen", tsiListen, "LISTEN"},
		{"syn sent", tsiSynSent, "SYN_SENT"},
		{"syn received", tsiSynReceived, "SYN_RCVD"},
		{"established", tsiEstablished, "ESTABLISHED"},
		{"close wait", tsiCloseWait, "CLOSE_WAIT"},
		{"fin wait 1", tsiFinWait1, "FIN_WAIT_1"},
		{"closing", tsiClosing, "CLOSING"},
		{"last ack", tsiLastAck, "LAST_ACK"},
		{"fin wait 2", tsiFinWait2, "FIN_WAIT_2"},
		{"time wait", tsiTimeWait, "TIME_WAIT"},
		{"no-state sentinel", -1, ""},
		{"unrecognised value", 99, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tcpStateName(tc.state); got != tc.want {
				t.Errorf("tcpStateName(%d) = %q, want %q", tc.state, got, tc.want)
			}
		})
	}
}

// TestCgoErr checks both of cgoErr's cases: a nil errno gets replaced with a
// placeholder rather than passed through, and a real error is returned
// unchanged.
func TestCgoErr(t *testing.T) {
	if err := cgoErr(nil); err == nil {
		t.Error("cgoErr(nil) = nil, want a non-nil placeholder error")
	}

	want := errors.New("boom")
	if got := cgoErr(want); got != want {
		t.Errorf("cgoErr(%v) = %v, want the same error unchanged", want, got)
	}
}
