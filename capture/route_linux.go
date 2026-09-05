//go:build linux

package capture

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

// loopbackInterface is the name of the Linux loopback device.
const loopbackInterface = "lo"

// runRoute invokes `ip -4 route show default` and returns its stdout. It is a
// variable so tests can substitute a stub and exercise DefaultInterface's
// fallback path without depending on the host's actual routing table.
var runRoute = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "ip", "-4", "route", "show", "default").Output()
}

// parseRouteInterface pulls the device name out of `ip -4 route show
// default` output, e.g. "default via 192.168.1.1 dev eth0 proto dhcp metric
// 100". Multiple default routes are listed lowest-metric (most preferred)
// first, so only the first line is considered.
func parseRouteInterface(out string) (string, error) {
	line, _, _ := strings.Cut(out, "\n")
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", errors.New("no interface in route output")
}
