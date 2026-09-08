package capture

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestLocalAddrSetRejectsUnknownInterface(t *testing.T) {
	if _, err := localAddrSet([]string{"nosuchif0"}); err == nil {
		t.Fatal("localAddrSet(nosuchif0) = nil error, want a lookup failure")
	}
}

// TestLocalAddrSetSkipsAnUnresolvableNameAmongOthers proves one bad name
// among several no longer aborts the whole lookup: the loopback interface's
// address alone is enough to satisfy it.
func TestLocalAddrSetSkipsAnUnresolvableNameAmongOthers(t *testing.T) {
	name, err := loopbackDeviceName()
	if err != nil {
		t.Skipf("loopbackDeviceName() error = %v", err)
	}

	set, err := localAddrSet([]string{name, "nosuchif0"})
	if err != nil {
		t.Fatalf("localAddrSet(%q, nosuchif0) error = %v, want the good name alone to succeed", name, err)
	}
	if len(set) == 0 {
		t.Fatal("localAddrSet() = empty set, want at least the loopback addresses")
	}
}

func TestResolveInterfacesLiteralNames(t *testing.T) {
	tests := []struct {
		spec string
		want []string
	}{
		{spec: "eth0", want: []string{"eth0"}},
		{spec: "eth0,eth1", want: []string{"eth0", "eth1"}},
		{spec: " eth0 , eth1 ", want: []string{"eth0", "eth1"}},
	}
	for _, tt := range tests {
		got, err := ResolveInterfaces(tt.spec)
		if err != nil {
			t.Fatalf("ResolveInterfaces(%q) error = %v", tt.spec, err)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ResolveInterfaces(%q) = %v, want %v", tt.spec, got, tt.want)
		}
	}
}

func TestResolveInterfacesAny(t *testing.T) {
	want, err := ListInterfaces()
	if err != nil {
		t.Skipf("ListInterfaces() error = %v", err)
	}

	got, err := ResolveInterfaces(Any)
	if err != nil {
		t.Fatalf("ResolveInterfaces(Any) error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ResolveInterfaces(Any) = %v, want %v", got, want)
	}
}

func TestResolveInterfacesEmptyIsAny(t *testing.T) {
	want, err := ResolveInterfaces(Any)
	if err != nil {
		t.Skipf("ResolveInterfaces(Any) error = %v", err)
	}

	got, err := ResolveInterfaces("")
	if err != nil {
		t.Fatalf(`ResolveInterfaces("") error = %v`, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf(`ResolveInterfaces("") = %v, want %v (same as Any)`, got, want)
	}
}

func TestResolveInterfacesLocalhostSynonyms(t *testing.T) {
	want, err := loopbackDeviceName()
	if err != nil {
		t.Skipf("loopbackDeviceName() error = %v", err)
	}

	for _, spec := range []string{"localhost", "local", "loopback", "LOCALHOST", "Local", "LoopBack"} {
		got, err := ResolveInterfaces(spec)
		if err != nil {
			t.Fatalf("ResolveInterfaces(%q) error = %v", spec, err)
		}
		if !reflect.DeepEqual(got, []string{want}) {
			t.Errorf("ResolveInterfaces(%q) = %v, want [%v]", spec, got, want)
		}
	}
}

func TestResolveInterfacesDefault(t *testing.T) {
	want, err := DefaultInterfaces()
	if err != nil {
		t.Skipf("DefaultInterfaces() error = %v", err)
	}

	got, err := ResolveInterfaces(Default)
	if err != nil {
		t.Fatalf("ResolveInterfaces(Default) error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ResolveInterfaces(Default) = %v, want %v", got, want)
	}
}

func TestResolveInterfacesMixedSpecDedupes(t *testing.T) {
	names, err := ListInterfaces()
	if err != nil || len(names) == 0 {
		t.Skipf("ListInterfaces() = %v, %v", names, err)
	}

	got, err := ResolveInterfaces(names[0] + "," + Any)
	if err != nil {
		t.Fatalf("ResolveInterfaces(%q) error = %v", names[0]+","+Any, err)
	}
	if !reflect.DeepEqual(got, names) {
		t.Errorf("ResolveInterfaces(%q) = %v, want %v (literal name deduplicated against Any's own expansion)", names[0]+","+Any, got, names)
	}
}

// TestDefaultInterfacesToleratesNoIPv6DefaultRoute stubs runRoute6 to fail,
// as most real networks will, and confirms DefaultInterfaces still succeeds
// off runRoute alone.
func TestDefaultInterfacesToleratesNoIPv6DefaultRoute(t *testing.T) {
	origRoute6 := runRoute6
	runRoute6 = func(_ context.Context) ([]byte, error) {
		return nil, errors.New("no ipv6 default route")
	}
	t.Cleanup(func() { runRoute6 = origRoute6 })

	names, err := DefaultInterfaces()
	if err != nil {
		t.Skipf("no capturable interface to fall back to: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("DefaultInterfaces() = empty slice, want at least one name")
	}
}

// withStubRoute substitutes runRoute for the duration of the test and
// restores it afterwards, so DefaultInterface's fallback path can be driven
// without depending on the host's actual routing table.
func withStubRoute(t *testing.T, stub func(ctx context.Context) ([]byte, error)) {
	t.Helper()
	orig := runRoute
	runRoute = stub
	t.Cleanup(func() { runRoute = orig })
}

func TestDefaultInterfaceFallsBackWhenRouteFails(t *testing.T) {
	withStubRoute(t, func(_ context.Context) ([]byte, error) {
		return nil, errors.New("route: writing to routing socket: not in table")
	})

	name, err := DefaultInterface()
	if err != nil {
		t.Skipf("no capturable interface to fall back to: %v", err)
	}
	if name == loopbackInterface {
		t.Errorf("DefaultInterface() = %q, want the fallback to skip the loopback device", name)
	}
}

func TestDefaultInterfaceFallsBackWhenRouteOutputIsUnrecognised(t *testing.T) {
	withStubRoute(t, func(_ context.Context) ([]byte, error) {
		return []byte("garbage output with no interface line\n"), nil
	})

	name, err := DefaultInterface()
	if err != nil {
		t.Skipf("no capturable interface to fall back to: %v", err)
	}
	if name == loopbackInterface {
		t.Errorf("DefaultInterface() = %q, want the fallback to skip the loopback device", name)
	}
}
