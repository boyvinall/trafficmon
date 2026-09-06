//go:build windows

package capture

import (
	"context"
	"net"
	"strconv"
	"testing"
)

func TestNPFGUIDExtractsGUID(t *testing.T) {
	name := `\Device\NPF_{4D36E972-E325-11CE-BFC1-08002BE10318}`
	guid, ok := npfGUID(name)
	if !ok || guid != "{4D36E972-E325-11CE-BFC1-08002BE10318}" {
		t.Fatalf("npfGUID(%q) = (%q, %v), want the embedded GUID", name, guid, ok)
	}
}

func TestNPFGUIDRejectsNonNPFName(t *testing.T) {
	if _, ok := npfGUID("Ethernet"); ok {
		t.Fatal("npfGUID(Ethernet) = ok, want false for a name with no NPF_ prefix")
	}
}

func TestResolveInterfaceRejectsUnknownGUID(t *testing.T) {
	name := `\Device\NPF_{00000000-0000-0000-0000-000000000000}`
	if _, err := resolveInterface(name); err == nil {
		t.Fatalf("resolveInterface(%q) = nil error, want a lookup failure for a GUID matching no adapter", name)
	}
}

func TestIsLoopbackInterface(t *testing.T) {
	names, err := ListInterfaces()
	if err != nil {
		t.Skipf("ListInterfaces() error = %v", err)
	}
	for _, name := range names {
		ifi, err := resolveInterface(name)
		if err != nil {
			t.Errorf("resolveInterface(%q) error = %v", name, err)
			continue
		}
		want := ifi.Flags&net.FlagLoopback != 0
		if got := isLoopbackInterface(name); got != want {
			t.Errorf("isLoopbackInterface(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestLoopbackDeviceNameIsLoopback(t *testing.T) {
	name, err := loopbackDeviceName()
	if err != nil {
		t.Skipf("loopbackDeviceName() error = %v", err)
	}
	if !isLoopbackInterface(name) {
		t.Fatalf("loopbackDeviceName() = %q, want a device isLoopbackInterface agrees on", name)
	}
}

func TestLocalAddrSetIncludesLoopback(t *testing.T) {
	name, err := loopbackDeviceName()
	if err != nil {
		t.Skipf("loopbackDeviceName() error = %v", err)
	}

	set, err := localAddrSet([]string{name})
	if err != nil {
		t.Fatalf("localAddrSet(%q) error = %v", name, err)
	}
	if _, found := set[mustAddr(t, "127.0.0.1")]; !found {
		t.Fatalf("localAddrSet(%q) = %v, want it to contain 127.0.0.1", name, set)
	}
}

func TestParseRouteInterfaceRejectsGarbage(t *testing.T) {
	if _, err := parseRouteInterface("not a number"); err == nil {
		t.Fatal("parseRouteInterface(garbage) = nil error, want a parse failure")
	}
}

func TestRunRoutePicksAResolvableInterface(t *testing.T) {
	out, err := runRoute(context.Background())
	if err != nil {
		t.Fatalf("runRoute() error = %v", err)
	}
	name, err := parseRouteInterface(string(out))
	if err != nil {
		t.Fatalf("parseRouteInterface(%q) error = %v", out, err)
	}
	if name == "" {
		t.Fatal(`parseRouteInterface() = "", want a real interface name`)
	}
}

// TestDefaultInterfaceUsesStubbedRoute exercises DefaultInterface's route
// path via withStubRoute (iface_test.go), matching the darwin/linux
// coverage of the same fallback.
func TestDefaultInterfaceUsesStubbedRoute(t *testing.T) {
	names, err := ListInterfaces()
	if err != nil || len(names) == 0 {
		t.Skip("no capturable interfaces available")
	}
	ifi, err := resolveInterface(names[0])
	if err != nil {
		t.Skipf("resolveInterface(%q) error = %v", names[0], err)
	}

	withStubRoute(t, func(_ context.Context) ([]byte, error) {
		return []byte(strconv.FormatUint(uint64(ifi.Index), 10)), nil
	})

	name, err := DefaultInterface()
	if err != nil {
		t.Fatalf("DefaultInterface() error = %v", err)
	}
	if name != names[0] {
		t.Errorf("DefaultInterface() = %q, want %q", name, names[0])
	}
}
