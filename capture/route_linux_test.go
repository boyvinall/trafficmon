//go:build linux

package capture

import "testing"

func TestParseRouteInterface(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		want    string
		wantErr bool
	}{
		{
			name: "typical default route",
			out:  "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n",
			want: "eth0",
		},
		{
			name: "vpn tunnel wins when it is the lowest-metric default route",
			out: "default dev tun0 proto static scope link metric 50\n" +
				"default via 192.168.1.1 dev eth0 proto dhcp metric 100\n",
			want: "tun0",
		},
		{
			name: "no trailing newline",
			out:  "default via 10.0.0.1 dev enp0s3 proto dhcp metric 1024",
			want: "enp0s3",
		},
		{
			name:    "no default route",
			out:     "",
			wantErr: true,
		},
		{
			name:    "output with no dev field",
			out:     "throw 10.0.0.0/8\n",
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
