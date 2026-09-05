//go:build darwin

package capture

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

// loopbackInterface is the name of the macOS loopback device.
const loopbackInterface = "lo0"

// runRoute invokes `route -n get default` and returns its stdout. It is a
// variable so tests can substitute a stub and exercise DefaultInterface's
// fallback path without depending on the host's actual routing table.
var runRoute = func(ctx context.Context) ([]byte, error) {
	// `route` writes the answer to stdout and diagnostics to stderr, so only
	// stdout is parsed. -n keeps it from stalling on reverse DNS.
	return exec.CommandContext(ctx, "route", "-n", "get", "default").Output()
}

// parseRouteInterface pulls the device name out of `route -n get default`
// output, which reports it on an indented "interface: en0" line.
func parseRouteInterface(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
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
