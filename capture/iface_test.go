package capture

import (
	"context"
	"errors"
	"testing"
)

func TestParseRouteInterface(t *testing.T) {
	// Verbatim output from `route -n get default` on macOS 15.
	const macOSDefault = `   route to: default
destination: default
       mask: default
    gateway: 10.44.96.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
`

	tests := []struct {
		name    string
		out     string
		want    string
		wantErr bool
	}{
		{
			name: "macOS default route",
			out:  macOSDefault,
			want: "en0",
		},
		{
			name: "vpn tunnel wins when it holds the default route",
			out:  "   route to: default\n  interface: utun4\n      flags: <UP,GATEWAY>\n",
			want: "utun4",
		},
		{
			name: "no trailing newline",
			out:  "  interface: en1",
			want: "en1",
		},
		{
			name:    "route reports no default",
			out:     "route: writing to routing socket: not in table\n",
			wantErr: true,
		},
		{
			name:    "interface line without a name",
			out:     "  interface: \n",
			wantErr: true,
		},
		{
			name:    "empty output",
			out:     "",
			wantErr: true,
		},
		{
			// "interface" must be the whole field name, not a prefix of some
			// other line's text.
			name:    "similar looking field",
			out:     "  interfaces: en0\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRouteInterface(tt.out)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseRouteInterface() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRouteInterface() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseRouteInterface() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLocalAddrSetIncludesLoopback(t *testing.T) {
	// lo0 always exists and always carries 127.0.0.1, so this needs no root
	// and no particular network configuration.
	set, err := localAddrSet([]string{loopbackInterface})
	if err != nil {
		t.Fatalf("localAddrSet() error = %v", err)
	}

	if _, found := set[mustAddr(t, "127.0.0.1")]; !found {
		t.Fatalf("localAddrSet(lo0) = %v, want it to contain 127.0.0.1", set)
	}
}

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
	withStubRoute(t, func(ctx context.Context) ([]byte, error) {
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
	withStubRoute(t, func(ctx context.Context) ([]byte, error) {
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
