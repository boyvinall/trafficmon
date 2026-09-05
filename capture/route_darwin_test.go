//go:build darwin

package capture

import "testing"

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
