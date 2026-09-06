//go:build windows

package procinfo

import (
	"net"
	"os"
	"slices"
	"testing"
)

func TestSocketsForPIDFindsOwnListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck // test cleanup

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	pid := int32(os.Getpid())

	sockets, err := SocketsForPID(pid)
	if err != nil {
		t.Fatalf("SocketsForPID: %v", err)
	}

	var found *Socket
	for i := range sockets {
		if sockets[i].Proto == "tcp" && sockets[i].LocalPort == port {
			found = &sockets[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("listener on port %d not found among %d sockets for pid %d", port, len(sockets), pid)
	}
	if found.PID != pid {
		t.Errorf("PID = %d, want %d", found.PID, pid)
	}
	if found.State != "LISTEN" {
		t.Errorf("State = %q, want LISTEN", found.State)
	}
}

func TestListPIDsIncludesSelf(t *testing.T) {
	pids, err := ListPIDs()
	if err != nil {
		t.Fatalf("ListPIDs: %v", err)
	}

	self := int32(os.Getpid())
	if !slices.Contains(pids, self) {
		t.Fatalf("own pid %d not found in %d listed pids", self, len(pids))
	}
}

func TestProcessNameSelf(t *testing.T) {
	name, err := ProcessName(int32(os.Getpid()))
	if err != nil {
		t.Fatalf("ProcessName: %v", err)
	}
	if name == "" {
		t.Error("ProcessName returned an empty name for the current process")
	}
}

func TestTCPStateName(t *testing.T) {
	cases := []struct {
		state uint32
		want  string
	}{
		{1, "CLOSED"},
		{2, "LISTEN"},
		{3, "SYN_SENT"},
		{4, "SYN_RCVD"},
		{5, "ESTABLISHED"},
		{6, "FIN_WAIT1"},
		{7, "FIN_WAIT2"},
		{8, "CLOSE_WAIT"},
		{9, "CLOSING"},
		{10, "LAST_ACK"},
		{11, "TIME_WAIT"},
		{12, ""},
		{0, ""},
		{99, ""},
	}
	for _, c := range cases {
		if got := tcpStateName(c.state); got != c.want {
			t.Errorf("tcpStateName(%d) = %q, want %q", c.state, got, c.want)
		}
	}
}

func TestSwapPort(t *testing.T) {
	// A DWORD whose low 16 bits hold 0x1F90 (8080) in network byte order,
	// i.e. the bytes 0x1F, 0x90 -- which a little-endian read packs into the
	// DWORD as 0x901F.
	if got := swapPort(0x901F); got != 8080 {
		t.Errorf("swapPort(0x901F) = %d, want 8080", got)
	}
}

func TestIPv4Addr(t *testing.T) {
	// 127.0.0.1 stored as a DWORD whose bytes, read little-endian, are
	// already in address order: 127, 0, 0, 1.
	addr := ipv4Addr(0x0100007F)
	if addr.String() != "127.0.0.1" {
		t.Errorf("ipv4Addr(0x0100007F) = %s, want 127.0.0.1", addr)
	}
}
