package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// loopbackInterface is the name of the macOS loopback device.
const loopbackInterface = "lo0"

// routeTimeout bounds how long the `route` lookup may block, so a hung or
// misbehaving binary cannot stall startup forever.
const routeTimeout = 3 * time.Second

// runRoute invokes `route -n get default` and returns its stdout. It is a
// variable so tests can substitute a stub and exercise DefaultInterface's
// fallback path without depending on the host's actual routing table.
var runRoute = func(ctx context.Context) ([]byte, error) {
	// `route` writes the answer to stdout and diagnostics to stderr, so only
	// stdout is parsed. -n keeps it from stalling on reverse DNS.
	return exec.CommandContext(ctx, "route", "-n", "get", "default").Output()
}

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
		if n != loopbackInterface {
			return n, nil
		}
	}
	return "", errors.New("no capturable interface found")
}

// parseRouteInterface pulls the device name out of `route -n get default`
// output, which reports it on an indented "interface: en0" line.
func parseRouteInterface(out string) (string, error) {
	for line := range strings.SplitSeq(out, "\n") {
		rest, found := strings.CutPrefix(strings.TrimSpace(line), "interface:")
		if !found {
			continue
		}
		if name := strings.TrimSpace(rest); name != "" {
			return name, nil
		}
	}
	return "", errors.New("no interface line in route output")
}

// localAddrSet collects the IP addresses configured on the named interfaces,
// which is what direction detection matches packets against.
//
// It is resolved once per run rather than per packet: addresses change rarely,
// and a lookup in the packet path would dominate the cost of decoding.
func localAddrSet(names []string) (map[netip.Addr]struct{}, error) {
	set := make(map[netip.Addr]struct{})

	for _, name := range names {
		ifi, err := net.InterfaceByName(name)
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
