//go:build !windows

package main

import (
	"fmt"
	"os"
)

// requirePrivileged checks that the process has the access packet capture
// and libproc need to see other users' sockets.
var requirePrivileged = func() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (try: sudo %s)", os.Args[0])
	}
	return nil
}
