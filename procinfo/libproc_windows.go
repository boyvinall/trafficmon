//go:build windows

package procinfo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ListPIDs returns every PID visible to the caller via a process-list
// snapshot. Unlike /proc or libproc, Windows requires no elevation to
// enumerate PIDs system-wide -- only per-process detail (e.g. another user's
// module list) is access-checked, and this call needs none of that.
func ListPIDs() ([]int32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot) //nolint:errcheck // a read-only snapshot handle's Close error carries nothing actionable

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	var out []int32
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if entry.ProcessID > 0 {
			out = append(out, int32(entry.ProcessID))
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, fmt.Errorf("Process32Next: %w", err)
	}
	return out, nil
}

// ProcessName returns the display name for pid: PROCESSENTRY32.szExeFile, the
// executable's basename as reported by the same Toolhelp32 snapshot ListPIDs
// uses. Windows exposes no argv[0] the way Unix exec does -- a process's
// command line is a single unparsed string it is free to format however it
// likes -- so this, not an argv0-style helper, is the Windows analogue of
// Darwin/Linux's ProcessName.
func ProcessName(pid int32) (string, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return "", fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot) //nolint:errcheck // a read-only snapshot handle's Close error carries nothing actionable

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if int32(entry.ProcessID) == pid {
			return windows.UTF16ToString(entry.ExeFile[:]), nil
		}
	}
	return "", fmt.Errorf("pid %d not found", pid)
}

// Socket describes one open socket belonging to a process.
//
// Addresses are netip.Addr rather than strings so that callers can compare
// them against capture-side addresses without worrying about IPv6 text
// formatting.
type Socket struct {
	PID        int32
	LocalPort  uint16
	RemotePort uint16
	LocalAddr  netip.Addr
	RemoteAddr netip.Addr
	Proto      string // "tcp" or "udp"
	// State is the TCP connection's kernel state (e.g. "ESTABLISHED",
	// "TIME_WAIT"), or "" for UDP and any other protocol with no state
	// concept.
	State string
}

// SocketsForPID returns every TCP/UDP socket owned by pid, including
// listening sockets: a listener owns its local port, and that is how inbound
// traffic to a server gets attributed to the process accepting it.
//
// Unlike Darwin's fd walk or Linux's /proc/net join, GetExtendedTcpTable/
// GetExtendedUdpTable already return each row's owning PID directly, so this
// only needs to filter one flat table rather than join two.
func SocketsForPID(pid int32) ([]Socket, error) {
	sockets, err := allSockets()
	if err != nil {
		return nil, err
	}

	out := sockets[:0]
	for _, s := range sockets {
		if s.PID == pid {
			out = append(out, s)
		}
	}
	return out, nil
}

// allSockets returns every TCP/UDP socket on the system across both address
// families, each already carrying its owning PID.
func allSockets() ([]Socket, error) {
	var out []Socket

	tcp4, err := tcpTable(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	out = append(out, tcp4...)

	tcp6, err := tcpTable(windows.AF_INET6)
	if err != nil {
		return nil, err
	}
	out = append(out, tcp6...)

	udp4, err := udpTable(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	out = append(out, udp4...)

	udp6, err := udpTable(windows.AF_INET6)
	if err != nil {
		return nil, err
	}
	out = append(out, udp6...)

	return out, nil
}

var (
	modIPHlpAPI             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modIPHlpAPI.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable = modIPHlpAPI.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPIDAll = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPID    = 1 // UDP_TABLE_OWNER_PID
)

// mibTCPRowOwnerPID mirrors MIB_TCPROW_OWNER_PID (iphlpapi.h): one IPv4 TCP
// row from GetExtendedTcpTable. LocalPort/RemotePort hold the port in network
// byte order within the low 16 bits, and LocalAddr/RemoteAddr hold the
// address's four octets in address order -- see swapPort/ipv4Addr.
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// mibTCP6RowOwnerPID mirrors MIB_TCP6ROW_OWNER_PID: one IPv6 TCP row.
// LocalAddr/RemoteAddr are already raw address bytes; LocalPort/RemotePort
// still need swapPort.
type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

// mibUDPRowOwnerPID mirrors MIB_UDPROW_OWNER_PID: one IPv4 UDP row. UDP has
// no state field.
type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

// mibUDP6RowOwnerPID mirrors MIB_UDP6ROW_OWNER_PID: one IPv6 UDP row.
type mibUDP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPID    uint32
}

// getExtendedTable calls fn (GetExtendedTcpTable or GetExtendedUdpTable)
// following its two-pass buffer-size protocol: an initial zero-length call
// reports the required size via ERROR_INSUFFICIENT_BUFFER, then a second
// call fills a buffer of that size. The table can grow between the two
// calls (a socket opening mid-query), so a growing size retries rather than
// erroring.
func getExtendedTable(fn *windows.LazyProc, family uint32, class uintptr) ([]byte, error) {
	var size uint32
	for range 8 {
		r1, _, _ := fn.Call(0, uintptr(unsafe.Pointer(&size)), 1, uintptr(family), class, 0) //nolint:gosec // passing &size to a Win32 API via syscall.Proc.Call
		if r1 != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil, fmt.Errorf("%s: sizing call returned %d", fn.Name, r1)
		}
		if size == 0 {
			return nil, nil
		}

		buf := make([]byte, size)
		r1, _, _ = fn.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(family), class, 0) //nolint:gosec // passing &buf[0]/&size to a Win32 API via syscall.Proc.Call
		switch r1 {
		case 0:
			return buf, nil
		case uintptr(windows.ERROR_INSUFFICIENT_BUFFER):
			continue // table grew between the two calls; retry with the new size
		default:
			return nil, fmt.Errorf("%s: %d", fn.Name, r1)
		}
	}
	return nil, fmt.Errorf("%s: table kept growing across every retry", fn.Name)
}

// tcpTable returns every IPv4 (AF_INET) or IPv6 (AF_INET6) TCP row. Every MIB
// *_OWNER_PID table shares the same header shape (a leading dwNumEntries
// DWORD, then a packed row array with no padding), so numEntries is read the
// same way regardless of family/protocol.
func tcpTable(family uint32) ([]Socket, error) {
	buf, err := getExtendedTable(procGetExtendedTCPTable, family, tcpTableOwnerPIDAll)
	if err != nil || buf == nil {
		return nil, err
	}
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	if numEntries == 0 {
		return nil, nil
	}

	out := make([]Socket, 0, numEntries)
	if family == windows.AF_INET6 {
		rows := unsafe.Slice((*mibTCP6RowOwnerPID)(unsafe.Pointer(&buf[4])), numEntries) //nolint:gosec // buf is sized and populated by GetExtendedTcpTable to hold exactly numEntries rows
		for _, r := range rows {
			s := Socket{
				PID:        int32(r.OwningPID),
				LocalAddr:  netip.AddrFrom16(r.LocalAddr).Unmap(),
				LocalPort:  swapPort(r.LocalPort),
				RemoteAddr: netip.AddrFrom16(r.RemoteAddr).Unmap(),
				RemotePort: swapPort(r.RemotePort),
				Proto:      "tcp",
				State:      tcpStateName(r.State),
			}
			if s.LocalPort != 0 {
				out = append(out, s)
			}
		}
		return out, nil
	}

	rows := unsafe.Slice((*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[4])), numEntries) //nolint:gosec // buf is sized and populated by GetExtendedTcpTable to hold exactly numEntries rows
	for _, r := range rows {
		s := Socket{
			PID:        int32(r.OwningPID),
			LocalAddr:  ipv4Addr(r.LocalAddr),
			LocalPort:  swapPort(r.LocalPort),
			RemoteAddr: ipv4Addr(r.RemoteAddr),
			RemotePort: swapPort(r.RemotePort),
			Proto:      "tcp",
			State:      tcpStateName(r.State),
		}
		if s.LocalPort != 0 {
			out = append(out, s)
		}
	}
	return out, nil
}

// udpTable returns every IPv4 (AF_INET) or IPv6 (AF_INET6) UDP row. UDP has
// no state concept, so Socket.State is always left "".
func udpTable(family uint32) ([]Socket, error) {
	buf, err := getExtendedTable(procGetExtendedUDPTable, family, udpTableOwnerPID)
	if err != nil || buf == nil {
		return nil, err
	}
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	if numEntries == 0 {
		return nil, nil
	}

	out := make([]Socket, 0, numEntries)
	if family == windows.AF_INET6 {
		rows := unsafe.Slice((*mibUDP6RowOwnerPID)(unsafe.Pointer(&buf[4])), numEntries) //nolint:gosec // buf is sized and populated by GetExtendedUdpTable to hold exactly numEntries rows
		for _, r := range rows {
			s := Socket{
				PID:       int32(r.OwningPID),
				LocalAddr: netip.AddrFrom16(r.LocalAddr).Unmap(),
				LocalPort: swapPort(r.LocalPort),
				Proto:     "udp",
			}
			if s.LocalPort != 0 {
				out = append(out, s)
			}
		}
		return out, nil
	}

	rows := unsafe.Slice((*mibUDPRowOwnerPID)(unsafe.Pointer(&buf[4])), numEntries) //nolint:gosec // buf is sized and populated by GetExtendedUdpTable to hold exactly numEntries rows
	for _, r := range rows {
		s := Socket{
			PID:       int32(r.OwningPID),
			LocalAddr: ipv4Addr(r.LocalAddr),
			LocalPort: swapPort(r.LocalPort),
			Proto:     "udp",
		}
		if s.LocalPort != 0 {
			out = append(out, s)
		}
	}
	return out, nil
}

// ipv4Addr converts a MIB row's dwLocalAddr/dwRemoteAddr field to a
// netip.Addr. The field holds the address's four octets in address order
// (network byte order), which a little-endian read of the DWORD's bytes
// reproduces directly -- unlike the port fields, no byte-swap is needed.
func ipv4Addr(raw uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(raw), byte(raw >> 8), byte(raw >> 16), byte(raw >> 24)})
}

// swapPort extracts a MIB row's port field. The port occupies the low 16
// bits of the DWORD in network byte order, so reading it as a little-endian
// value leaves its two bytes swapped relative to the actual port number.
func swapPort(raw uint32) uint16 {
	p := uint16(raw)
	return p<<8 | p>>8
}

// tcpStateName maps a TCP socket's MIB_TCP_STATE value (1-12) to Windows' own
// kernel state name. Any value this does not recognise falls back to "", the
// same as no state at all, rather than surfacing a kernel constant nobody
// would recognise.
func tcpStateName(state uint32) string {
	switch state {
	case 1:
		return "CLOSED"
	case 2:
		return "LISTEN"
	case 3:
		return "SYN_SENT"
	case 4:
		return "SYN_RCVD"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN_WAIT1"
	case 7:
		return "FIN_WAIT2"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST_ACK"
	case 11:
		return "TIME_WAIT"
	default:
		return ""
	}
}
