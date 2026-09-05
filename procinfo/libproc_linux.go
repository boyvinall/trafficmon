//go:build linux

package procinfo

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procNameBufSize bounds the buffer ProcessName reads /proc/<pid>/comm into.
// Linux caps a task's comm at 16 bytes (TASK_COMM_LEN); this leaves generous
// margin.
const procNameBufSize = 64

// ListPIDs returns every PID visible to the caller. Without root this is
// limited to the current user's processes: /proc/<pid> for another user's
// process exists but its fd/net entries are unreadable.
func ListPIDs() ([]int32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	out := make([]int32, 0, len(entries))
	for _, e := range entries {
		pid, err := strconv.ParseInt(e.Name(), 10, 32)
		if err != nil || pid <= 0 {
			// /proc holds plenty of non-numeric entries (self, net, sys, ...).
			continue
		}
		out = append(out, int32(pid))
	}
	return out, nil
}

// ProcessName returns the display name for pid: argv[0] as the process
// itself chose to present it, matching what ps(1) shows in its COMMAND
// column, with any directory component stripped. This falls back to the
// kernel's own /proc/<pid>/comm when argv cannot be read -- e.g. pid belongs
// to another user and we are not root, it has already exited, or it is a
// kernel thread with no argv at all.
//
// Preferring argv[0] matters because comm is the basename of the executable
// *path*, not the name the process presents: self-updating apps routinely
// exec a version- or hash-named binary while keeping argv[0] stable and
// friendly, and comm alone would surface the former.
func ProcessName(pid int32) (string, error) {
	if name, ok := argv0(pid); ok {
		return filepath.Base(name), nil
	}

	buf, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", fmt.Errorf("read comm for pid %d: %w", pid, err)
	}
	name := strings.TrimSuffix(string(buf), "\n")
	if name == "" {
		return "", fmt.Errorf("empty comm for pid %d", pid)
	}
	if len(name) > procNameBufSize {
		name = name[:procNameBufSize]
	}
	return name, nil
}

// argv0 returns pid's argv[0], or ok == false if it could not be read.
func argv0(pid int32) (name string, ok bool) {
	buf, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(buf) == 0 {
		// A kernel thread's cmdline is empty; an exited or other-user process
		// is unreadable. Either way the caller falls back to comm.
		return "", false
	}
	field, _, _ := strings.Cut(string(buf), "\x00")
	if field == "" {
		return "", false
	}
	return field, true
}

// Socket describes one open socket fd belonging to a process.
//
// Addresses are netip.Addr rather than strings so that callers can compare them
// against capture-side addresses without worrying about IPv6 text formatting.
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

// procNetEntry is one row of /proc/net/{tcp,tcp6,udp,udp6}, keyed by its
// socket inode for the fd walk in SocketsForPID to join against.
type procNetEntry struct {
	localAddr, remoteAddr netip.Addr
	localPort, remotePort uint16
	proto                 string
	state                 string
}

// SocketsForPID walks pid's file descriptors and returns every TCP or UDP
// socket among them, including listening sockets: a listener owns its local
// port, and that is how inbound traffic to a server gets attributed to the
// process accepting it.
//
// Sockets that are not yet bound (local port zero) are dropped, since they own
// no port to join traffic against. Errors from an individual descriptor are
// swallowed: fds are closed underneath us all the time, and one racing fd
// should not lose the whole process.
func SocketsForPID(pid int32) ([]Socket, error) {
	byInode, err := readProcNet()
	if err != nil {
		return nil, err
	}

	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", fdDir, err)
	}

	out := make([]Socket, 0, len(entries))
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		inodeStr, ok := strings.CutPrefix(target, "socket:[")
		if !ok {
			continue
		}
		inodeStr = strings.TrimSuffix(inodeStr, "]")
		inode, err := strconv.ParseUint(inodeStr, 10, 64)
		if err != nil {
			continue
		}

		entry, ok := byInode[inode]
		if !ok || entry.localPort == 0 {
			continue
		}

		out = append(out, Socket{
			PID:        pid,
			LocalPort:  entry.localPort,
			RemotePort: entry.remotePort,
			LocalAddr:  entry.localAddr,
			RemoteAddr: entry.remoteAddr,
			Proto:      entry.proto,
			State:      entry.state,
		})
	}

	return out, nil
}

// readProcNet parses /proc/net/{tcp,tcp6,udp,udp6} into a table keyed by
// socket inode, which SocketsForPID joins against the inodes named by a
// process's own fd symlinks. It is parsed fresh on every call rather than
// cached across the poll's PID loop: the four files are small, and this
// keeps the poller's PID walk (procinfo/poller.go) untouched.
func readProcNet() (map[uint64]procNetEntry, error) {
	out := make(map[uint64]procNetEntry)
	for _, f := range []struct {
		path  string
		proto string
	}{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp"},
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp"},
	} {
		if err := parseProcNetFile(f.path, f.proto, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// parseProcNetFile parses one /proc/net/{tcp,tcp6,udp,udp6} file into out,
// keyed by inode. A missing file (e.g. tcp6/udp6 with IPv6 disabled) is not
// an error.
func parseProcNetFile(path, proto string, out map[uint64]procNetEntry) error {
	f, err := os.Open(path) //nolint:gosec // path is always one of our own four hardcoded /proc/net/* names, never attacker-controlled
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // a read-only fd's Close error carries nothing actionable

	sc := bufio.NewScanner(f)
	sc.Scan() // discard the header line
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}

		localAddr, localPort, err := parseHexAddrPort(fields[1])
		if err != nil {
			continue
		}
		remoteAddr, remotePort, err := parseHexAddrPort(fields[2])
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || inode == 0 {
			continue
		}

		state := ""
		if proto == "tcp" {
			st, err := strconv.ParseUint(fields[3], 16, 8)
			if err != nil {
				continue
			}
			state = tcpStateName(int(st))
		}

		out[inode] = procNetEntry{
			localAddr:  localAddr,
			localPort:  localPort,
			remoteAddr: remoteAddr,
			remotePort: remotePort,
			proto:      proto,
			state:      state,
		}
	}
	return sc.Err()
}

// parseHexAddrPort parses one "ADDRHEX:PORTHEX" field as found in
// /proc/net/{tcp,udp}[6].
//
// The kernel prints an IPv4 address as a single 32-bit word, and an IPv6
// address as four 32-bit words -- in both cases in the machine's native
// (little-endian, on every Linux port that runs a Go build) word order
// rather than network byte order, so each 4-byte group is byte-reversed
// here; the four groups of an IPv6 address otherwise stay in address order.
func parseHexAddrPort(s string) (netip.Addr, uint16, error) {
	addrHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("malformed address:port %q", s)
	}

	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("parse port %q: %w", portHex, err)
	}

	raw, err := hex.DecodeString(addrHex)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("parse address %q: %w", addrHex, err)
	}

	switch len(raw) {
	case 4:
		return netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]}), uint16(port), nil
	case 16:
		var b [16]byte
		for w := 0; w < 4; w++ {
			b[w*4+0], b[w*4+1], b[w*4+2], b[w*4+3] = raw[w*4+3], raw[w*4+2], raw[w*4+1], raw[w*4+0]
		}
		return netip.AddrFrom16(b).Unmap(), uint16(port), nil
	default:
		return netip.Addr{}, 0, fmt.Errorf("address %q is %d bytes, want 4 or 16", addrHex, len(raw))
	}
}

// tcpStateName maps a TCP socket's kernel state (the hex st column of
// /proc/net/tcp[6], per include/net/tcp_states.h) to Linux's own state name.
// Any value this does not recognise falls back to "", the same as no state
// at all, rather than surfacing a kernel constant nobody would recognise.
func tcpStateName(state int) string {
	switch state {
	case 0x01:
		return "ESTABLISHED"
	case 0x02:
		return "SYN_SENT"
	case 0x03:
		return "SYN_RECV"
	case 0x04:
		return "FIN_WAIT1"
	case 0x05:
		return "FIN_WAIT2"
	case 0x06:
		return "TIME_WAIT"
	case 0x07:
		return "CLOSE"
	case 0x08:
		return "CLOSE_WAIT"
	case 0x09:
		return "LAST_ACK"
	case 0x0A:
		return "LISTEN"
	case 0x0B:
		return "CLOSING"
	default:
		return ""
	}
}
