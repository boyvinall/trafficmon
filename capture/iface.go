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

// Interface-spec keywords recognised in Config.Interface (and by
// ResolveInterfaces directly), case-insensitively, alongside literal
// device names in a comma-separated list — e.g. "eth0,loopback". An empty
// spec is treated as Any.
const (
	// Any selects every interface libpcap can see. It is DefaultConfig's
	// own default.
	Any = "any"
	// Default selects every interface currently backing a default route —
	// there can be more than one, e.g. a different interface for the IPv4
	// and IPv6 default routes.
	Default = "default"
	// Localhost selects the platform's loopback interface. "local" and
	// "loopback" are accepted as synonyms in a spec string, but this is
	// the one Go callers get a name for.
	Localhost = "localhost"
)

// ResolveInterfaces expands an interface spec into the concrete,
// deduplicated set of libpcap device names it names, in first-seen order.
// Unknown keywords are never guessed at: anything that isn't Any, Default,
// Localhost, or one of Localhost's "local"/"loopback" synonyms is taken as
// a literal device name, unresolved and unvalidated until Run actually
// tries to open it.
func ResolveInterfaces(spec string) ([]string, error) {
	if strings.TrimSpace(spec) == "" {
		spec = Any
	}

	var (
		out  []string
		seen = make(map[string]struct{})
	)
	add := func(name string) {
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}

	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}

		switch strings.ToLower(tok) {
		case Any:
			names, err := ListInterfaces()
			if err != nil {
				return nil, err
			}
			for _, n := range names {
				add(n)
			}
		case Default:
			names, err := DefaultInterfaces()
			if err != nil {
				return nil, err
			}
			for _, n := range names {
				add(n)
			}
		case Localhost, "local", "loopback":
			name, err := loopbackDeviceName()
			if err != nil {
				return nil, err
			}
			add(name)
		default:
			add(tok)
		}
	}

	return out, nil
}

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

// DefaultInterfaces resolves every interface currently backing a default
// route: whichever carries the IPv4 default route, the IPv6 default
// route, or both if they differ, mirroring what `route get default` /
// `route get -inet6 default` report. Falls back to the first non-loopback
// device libpcap offers if neither route lookup succeeds, same as
// DefaultInterface always has.
func DefaultInterfaces() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), routeTimeout)
	defer cancel()

	var (
		out  []string
		seen = make(map[string]struct{})
	)
	add := func(name string) {
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}

	if out4, err := runRoute(ctx); err == nil {
		if name, perr := parseRouteInterface(string(out4)); perr == nil {
			add(name)
		}
	}
	if out6, err := runRoute6(ctx); err == nil {
		if name, perr := parseRouteInterface(string(out6)); perr == nil {
			add(name)
		}
	}
	if len(out) > 0 {
		return out, nil
	}

	// No default route, or output we did not recognise: fall back to the
	// first real device libpcap offers, which is usually the right guess on
	// a machine with a single uplink.
	names, err := ListInterfaces()
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		if !isLoopbackInterface(n) {
			return []string{n}, nil
		}
	}
	return nil, errors.New("no capturable interface found")
}

// DefaultInterface is DefaultInterfaces narrowed to one name, for callers
// that only want a single best guess.
func DefaultInterface() (string, error) {
	names, err := DefaultInterfaces()
	if err != nil {
		return "", err
	}
	return names[0], nil
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
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
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
