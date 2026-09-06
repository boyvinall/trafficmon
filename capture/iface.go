package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// routeTimeout bounds how long the route lookup may block, so a hung or
// misbehaving binary cannot stall startup forever.
const routeTimeout = 3 * time.Second

// loopbackInterface is the name of the platform's loopback device, and
// runRoute/parseRouteInterface find the interface backing the default route
// by shelling out to the platform's own routing-table tool. All three are
// defined per-OS: see route_darwin.go and route_linux.go. runRoute is a
// variable so tests can substitute a stub and exercise DefaultInterface's
// fallback path without depending on the host's actual routing table.
//
// resolveInterface and isLoopbackInterface are also variables, one
// implementation shared by Darwin/Linux (route_other.go) and one for Windows
// (route_windows.go), where a libpcap device name isn't the OS's own
// interface name and the loopback device has no stable name to compare
// against.

// DefaultInterface resolves the interface backing the default route, mirroring
// what `route get default` reports — the same trick iftop uses to pick an
// interface with no flags given.
func DefaultInterface() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), routeTimeout)
	defer cancel()

	out, err := runRoute(ctx)
	if err == nil {
		if name, perr := parseRouteInterface(string(out)); perr == nil {
			return name, nil
		}
	}

	// No default route, or output we did not recognise: fall back to the
	// first real device libpcap offers, which is usually the right guess on
	// a machine with a single uplink.
	names, err := ListInterfaces()
	if err != nil {
		return "", err
	}
	for _, n := range names {
		if !isLoopbackInterface(n) {
			return n, nil
		}
	}
	return "", errors.New("no capturable interface found")
}

// localAddrSet collects the IP addresses configured on the named interfaces,
// which is what direction detection matches packets against.
//
// It is resolved once per run rather than per packet: addresses change rarely,
// and a lookup in the packet path would dominate the cost of decoding.
func localAddrSet(names []string) (map[netip.Addr]struct{}, error) {
	set := make(map[netip.Addr]struct{})

	for _, name := range names {
		ifi, err := resolveInterface(name)
		if err != nil {
			return nil, fmt.Errorf("interface %s: %w", name, err)
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			return nil, fmt.Errorf("addresses of %s: %w", name, err)
		}
		for _, a := range addrs {
			ipnet, isIPNet := a.(*net.IPNet)
			if !isIPNet {
				continue
			}
			addr, valid := netip.AddrFromSlice(ipnet.IP)
			if !valid {
				continue
			}
			// Unmap so a 4-in-6 form of an IPv4 address compares equal to the
			// plain IPv4 address a decoded packet yields.
			set[addr.Unmap()] = struct{}{}
		}
	}

	if len(set) == 0 {
		return nil, fmt.Errorf("no IP addresses on %s", strings.Join(names, ", "))
	}
	return set, nil
}
