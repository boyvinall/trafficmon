//go:build darwin

package procinfo

/*
#include <arpa/inet.h>
#include <errno.h>
#include <libproc.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>

// mn_sock_addrs is a union-free view of the parts of a struct socket_fdinfo we
// need. Go cannot address C unions -- cgo renders them as opaque byte arrays --
// so every union access lives on the C side where the layout is defined by the
// compiler rather than by hand-computed offsets.
typedef struct {
	int      kind;     // SOCKINFO_TCP or SOCKINFO_IN
	int      protocol; // IPPROTO_TCP, IPPROTO_UDP, ...
	int      is_v6;    // non-zero when laddr/faddr hold 16 address bytes
	uint16_t lport;    // host byte order
	uint16_t fport;    // host byte order
	uint8_t  laddr[16];
	uint8_t  faddr[16];
} mn_sock_addrs;

// mn_read_sock_addrs copies the addressing information out of fdi. It returns 0
// for socket kinds that carry no IP addressing at all (unix domain, kernel
// event, kernel control, vsock), which the caller skips.
static int mn_read_sock_addrs(const struct socket_fdinfo *fdi, mn_sock_addrs *out) {
	const struct in_sockinfo *ini;

	switch (fdi->psi.soi_kind) {
	case SOCKINFO_TCP:
		ini = &fdi->psi.soi_proto.pri_tcp.tcpsi_ini;
		break;
	case SOCKINFO_IN:
		ini = &fdi->psi.soi_proto.pri_in;
		break;
	default:
		return 0;
	}

	memset(out, 0, sizeof(*out));
	out->kind = fdi->psi.soi_kind;
	out->protocol = fdi->psi.soi_protocol;

	// insi_lport/insi_fport are declared int but hold a 16-bit port in network
	// byte order in their low half.
	out->lport = ntohs((uint16_t)ini->insi_lport);
	out->fport = ntohs((uint16_t)ini->insi_fport);

	// A dual-stack socket sets both flags, and a v6 socket holding a v4-mapped
	// address reports INI_IPV4 alone with the address in the v4 arm of the
	// union. Testing v4 first therefore gets both cases right; only a socket
	// that is purely v6 lands in the second branch.
	if (ini->insi_vflag & INI_IPV4) {
		out->is_v6 = 0;
		memcpy(out->laddr, &ini->insi_laddr.ina_46.i46a_addr4, 4);
		memcpy(out->faddr, &ini->insi_faddr.ina_46.i46a_addr4, 4);
	} else if (ini->insi_vflag & INI_IPV6) {
		out->is_v6 = 1;
		memcpy(out->laddr, &ini->insi_laddr.ina_6, 16);
		memcpy(out->faddr, &ini->insi_faddr.ina_6, 16);
	} else {
		return 0;
	}
	return 1;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"net/netip"
	"unsafe"
)

// ListPIDs returns every PID visible to the caller. Without root this is
// limited to the current user's processes.
func ListPIDs() ([]int32, error) {
	// A zero buffer asks the kernel how many bytes the full list needs.
	n, err := C.proc_listpids(C.PROC_ALL_PIDS, 0, nil, 0)
	if n <= 0 {
		return nil, fmt.Errorf("proc_listpids (sizing): %w", err)
	}

	buf := make([]int32, n/C.int(unsafe.Sizeof(C.int(0))))
	n, err = C.proc_listpids(C.PROC_ALL_PIDS, 0, unsafe.Pointer(&buf[0]), C.int(len(buf))*C.int(unsafe.Sizeof(C.int(0))))
	if n <= 0 {
		return nil, fmt.Errorf("proc_listpids: %w", err)
	}

	count := int(n) / int(unsafe.Sizeof(C.int(0)))
	pids := buf[:count]

	// The kernel pads the tail with zeroes; drop them.
	out := pids[:0]
	for _, pid := range pids {
		if pid > 0 {
			out = append(out, pid)
		}
	}
	return out, nil
}

// ProcessName returns the executable name for pid.
func ProcessName(pid int32) (string, error) {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n, err := C.proc_name(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return "", fmt.Errorf("proc_name(%d): %w", pid, err)
	}
	return string(buf[:n]), nil
}

// Socket describes one open socket fd belonging to a process.
//
// Addresses are netip.Addr rather than strings so that callers can compare them
// against capture-side addresses without worrying about IPv6 text formatting.
// An address is invalid (LocalAddr.IsValid() == false) only when the kernel
// reported no address at all; a listening socket instead reports the unspecified
// address and a zero RemotePort.
type Socket struct {
	PID        int32
	LocalPort  uint16
	RemotePort uint16
	LocalAddr  netip.Addr
	RemoteAddr netip.Addr
	Proto      string // "tcp" or "udp"
}

// SocketsForPID walks pid's file descriptors and returns every TCP or UDP
// socket among them, including listening sockets: a listener owns its local
// port, and that is how inbound traffic to a server gets attributed to the
// process accepting it.
//
// Sockets that are not yet bound (local port zero) are dropped, since they own
// no port to join traffic against, as are raw and ICMP sockets, which have no
// ports at all.
//
// Errors from individual descriptors are swallowed: fds are closed underneath
// us all the time, and one racing fd should not lose the whole process.
func SocketsForPID(pid int32) ([]Socket, error) {
	fds, err := listFDs(pid)
	if err != nil {
		return nil, err
	}

	var (
		out []Socket
		fdi C.struct_socket_fdinfo
	)
	size := C.int(unsafe.Sizeof(fdi))

	for i := range fds {
		if fds[i].proc_fdtype != C.PROX_FDTYPE_SOCKET {
			continue
		}

		n, _ := C.proc_pidfdinfo(C.int(pid), fds[i].proc_fd, C.PROC_PIDFDSOCKETINFO, unsafe.Pointer(&fdi), size)
		if n < size {
			// Short reads mean the fd went away or is not really a socket.
			continue
		}

		var addrs C.mn_sock_addrs
		if C.mn_read_sock_addrs(&fdi, &addrs) == 0 {
			continue
		}

		proto := protoName(addrs)
		if proto == "" || addrs.lport == 0 {
			continue
		}

		out = append(out, Socket{
			PID:        pid,
			LocalPort:  uint16(addrs.lport),
			RemotePort: uint16(addrs.fport),
			LocalAddr:  sockAddr(addrs.laddr, addrs.is_v6 != 0),
			RemoteAddr: sockAddr(addrs.faddr, addrs.is_v6 != 0),
			Proto:      proto,
		})
	}

	return out, nil
}

// listFDs returns pid's open file descriptor table.
func listFDs(pid int32) ([]C.struct_proc_fdinfo, error) {
	// A nil buffer asks how many bytes the table currently needs.
	n, err := C.proc_pidinfo(C.int(pid), C.PROC_PIDLISTFDS, 0, nil, 0)
	if n <= 0 {
		// A vanished or inaccessible process reports zero with ESRCH/EPERM.
		return nil, fmt.Errorf("proc_pidinfo(%d, PROC_PIDLISTFDS) sizing: %w", pid, cgoErr(err))
	}

	// Ask for more than the sizing call reported: the process is free to open
	// further descriptors in between the two calls, and a full buffer is
	// indistinguishable from a truncated one.
	size := C.int(unsafe.Sizeof(C.struct_proc_fdinfo{}))
	count := int(n)/int(size) + 16

	buf := make([]C.struct_proc_fdinfo, count)
	n, err = C.proc_pidinfo(C.int(pid), C.PROC_PIDLISTFDS, 0, unsafe.Pointer(&buf[0]), C.int(count)*size)
	if n <= 0 {
		return nil, fmt.Errorf("proc_pidinfo(%d, PROC_PIDLISTFDS): %w", pid, cgoErr(err))
	}

	got := int(n) / int(size)
	if got > count {
		got = count
	}
	return buf[:got], nil
}

// protoName maps a socket's kind and protocol number onto the names the rest of
// the program uses, returning "" for socket types we do not track.
func protoName(addrs C.mn_sock_addrs) string {
	if addrs.kind == C.SOCKINFO_TCP {
		return "tcp"
	}
	switch addrs.protocol {
	case C.IPPROTO_TCP:
		return "tcp"
	case C.IPPROTO_UDP:
		return "udp"
	default:
		return ""
	}
}

// sockAddr converts the raw address bytes from mn_sock_addrs into a netip.Addr.
func sockAddr(raw [16]C.uint8_t, v6 bool) netip.Addr {
	b := *(*[16]byte)(unsafe.Pointer(&raw))
	if v6 {
		// Unmap so that a v4-mapped v6 address compares equal to the plain v4
		// address the capture side will see on the wire.
		return netip.AddrFrom16(b).Unmap()
	}
	return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
}

// cgoErr guards against a syscall that fails without setting errno, which would
// otherwise be wrapped as a nil error and print as garbage.
func cgoErr(err error) error {
	if err == nil {
		return errors.New("no error reported")
	}
	return err
}
