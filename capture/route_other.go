//go:build !windows

package capture

import "net"

// resolveInterface resolves a libpcap device name to its net.Interface. On
// Darwin/Linux libpcap's device names are already the OS's own interface
// names, so this is a direct lookup; see route_windows.go for the Windows
// override, where libpcap hands back a raw NPF device path instead.
var resolveInterface = net.InterfaceByName

// isLoopbackInterface reports whether name is the platform's loopback
// device; see route_windows.go for the Windows override, which has no
// stable name to compare against.
var isLoopbackInterface = func(name string) bool {
	return name == loopbackInterface
}

// loopbackDeviceName returns the libpcap device name backing the loopback
// interface, for opening a second capture handle when IncludeLoopback is
// set; see route_windows.go for the Windows override, where the libpcap
// device name isn't a constant and must be discovered by enumeration.
var loopbackDeviceName = func() (string, error) {
	return loopbackInterface, nil
}
