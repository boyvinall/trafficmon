package capture

import (
	"context"
	"errors"
	"testing"
)

func TestLocalAddrSetRejectsUnknownInterface(t *testing.T) {
	if _, err := localAddrSet([]string{"nosuchif0"}); err == nil {
		t.Fatal("localAddrSet(nosuchif0) = nil error, want a lookup failure")
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
