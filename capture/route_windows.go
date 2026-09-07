//go:build windows

package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/boyvinall/trafficmon/capture/pcapdrv"
)

// loopbackInterface has no meaningful value on Windows: the loopback
// adapter's name varies by locale and version (see isLoopbackInterface
// below), so nothing can be compared against a constant here. Left empty
// purely so the cross-platform loopbackInterface references elsewhere in
// this package still compile.
const loopbackInterface = ""

// npfGUID pulls the adapter GUID out of a libpcap NPF device name, e.g.
// `\Device\NPF_{4D36E972-E325-11CE-BFC1-08002BE10318}`.
func npfGUID(name string) (string, bool) {
	_, guid, ok := strings.Cut(name, "NPF_")
	if !ok {
		return "", false
	}
	if j := strings.IndexByte(guid, '\\'); j >= 0 {
		guid = guid[:j]
	}
	return guid, guid != ""
}

// adapterAddresses calls GetAdaptersAddresses, growing its buffer until the
// call succeeds, and returns the head of the returned linked list.
func adapterAddresses() (*windows.IpAdapterAddresses, error) {
	const flags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER

	size := uint32(15000)
	for {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])) //nolint:gosec // buf is sized to hold the adapter list GetAdaptersAddresses fills in-place
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, aa, &size)
		if err == nil {
			return aa, nil
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
	}
}

// npcapLoopbackDevice is the fixed libpcap device name Npcap's loopback
// pseudo-adapter uses (`\Device\NPF_Loopback`). Unlike every other device,
// it isn't backed by a real network adapter, so it carries no GUID for
// GetAdaptersAddresses to match against and needs its own resolution path.
const npcapLoopbackDevice = "NPF_Loopback"

// resolveInterface resolves a libpcap NPF device name to its net.Interface
// by matching the GUID embedded in the device name against
// IP_ADAPTER_ADDRESSES.AdapterName, which carries that same GUID string.
var resolveInterface = func(name string) (*net.Interface, error) {
	if strings.HasSuffix(name, npcapLoopbackDevice) {
		return firstLoopbackInterface()
	}

	guid, ok := npfGUID(name)
	if !ok {
		return nil, fmt.Errorf("interface %s: no NPF adapter GUID found", name)
	}

	aa, err := adapterAddresses()
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", name, err)
	}
	for ; aa != nil; aa = aa.Next {
		if windows.BytePtrToString(aa.AdapterName) == guid {
			return net.InterfaceByIndex(int(aa.IfIndex))
		}
	}
	return nil, fmt.Errorf("interface %s: no adapter matching GUID %s", name, guid)
}

// firstLoopbackInterface returns the OS's own loopback interface, found by
// flag rather than name since Windows' loopback adapter name varies by
// locale and version.
func firstLoopbackInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("net.Interfaces: %w", err)
	}
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagLoopback != 0 {
			return &ifaces[i], nil
		}
	}
	return nil, errors.New("no loopback interface found")
}

// isLoopbackInterface reports whether name -- a libpcap NPF device name, the
// same currency every caller in this package deals in -- resolves to the
// loopback device. Windows' loopback adapter name varies by locale and
// version, so there is no constant to compare against like Darwin's
// lo0/Linux's lo; resolveInterface is what turns the NPF name into a real
// net.Interface to check the flag on.
var isLoopbackInterface = func(name string) bool {
	ifi, err := resolveInterface(name)
	if err != nil {
		return false
	}
	return ifi.Flags&net.FlagLoopback != 0
}

// loopbackDeviceName finds the libpcap NPF device name backing the loopback
// interface: unlike Darwin/Linux, Windows has no constant device name for
// it, so it must be discovered by resolving every device libpcap offers and
// checking which one's flags say loopback.
var loopbackDeviceName = func() (string, error) {
	names, err := pcapdrv.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("pcapdrv.FindAllDevs: %w", err)
	}
	for _, name := range names {
		if isLoopbackInterface(name) {
			return name, nil
		}
	}
	return "", errors.New("no loopback device found")
}

// runRoute asks the IP Helper API which interface would carry traffic to a
// public address and returns its index as decimal bytes, for
// parseRouteInterface to resolve into a name — mirroring the role `route -n
// get default` plays on Darwin and `ip route show default` on Linux, without
// the fragility of parsing locale-dependent `route print` text output.
var runRoute = func(_ context.Context) ([]byte, error) {
	sa := &windows.SockaddrInet4{Addr: [4]byte{8, 8, 8, 8}}
	var idx uint32
	if err := windows.GetBestInterfaceEx(sa, &idx); err != nil {
		return nil, fmt.Errorf("GetBestInterfaceEx: %w", err)
	}
	return []byte(strconv.FormatUint(uint64(idx), 10)), nil
}

// parseRouteInterface resolves the interface index runRoute found into the
// libpcap NPF device name backing it -- every other caller of DefaultInterface
// treats its return value as a libpcap device name (ListInterfaces, --iface,
// pcapdrv.OpenLive), and on Windows that name is never the OS's own interface
// name (net.Interface.Name), unlike Darwin's en0/Linux's eth0 where the two
// coincide.
func parseRouteInterface(out string) (string, error) {
	idx, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return "", fmt.Errorf("parse interface index: %w", err)
	}
	return deviceNameForIndex(uint32(idx))
}

// deviceNameForIndex resolves an interface index to the libpcap NPF device
// name backing it, the reverse of resolveInterface: it looks up the GUID
// GetAdaptersAddresses reports for that index, then matches it against every
// device name libpcap offers.
func deviceNameForIndex(idx uint32) (string, error) {
	aa, err := adapterAddresses()
	if err != nil {
		return "", fmt.Errorf("interface index %d: %w", idx, err)
	}
	var guid string
	for ; aa != nil; aa = aa.Next {
		if aa.IfIndex == idx {
			guid = windows.BytePtrToString(aa.AdapterName)
			break
		}
	}
	if guid == "" {
		return "", fmt.Errorf("interface index %d: no adapter found", idx)
	}

	names, err := pcapdrv.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("pcapdrv.FindAllDevs: %w", err)
	}
	for _, name := range names {
		if g, ok := npfGUID(name); ok && g == guid {
			return name, nil
		}
	}
	return "", fmt.Errorf("interface index %d: no libpcap device matching GUID %s", idx, guid)
}
