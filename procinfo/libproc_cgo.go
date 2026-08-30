//go:build darwin

package procinfo

/*
#include <errno.h>
#include <libproc.h>
#include <stdlib.h>
#include <sys/proc_info.h>
*/
import "C"

import (
	"fmt"
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
type Socket struct {
	PID        int32
	LocalPort  uint16
	RemotePort uint16
	LocalAddr  string
	RemoteAddr string
	Proto      string // "tcp" or "udp"
}

// SocketsForPID walks pid's file descriptors and returns every socket among
// them.
//
// TODO(milestone 2): proc_pidinfo(pid, PROC_PIDLISTFDS, ...) to enumerate fds,
// then proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, ...) for each fd whose
// proc_fdtype is PROX_FDTYPE_SOCKET. Read the addresses out of
// socket_fdinfo.psi.soi_proto.pri_tcp / pri_in, honouring soi_family for the
// v4/v6 union.
func SocketsForPID(pid int32) ([]Socket, error) {
	_ = pid
	return nil, nil
}
