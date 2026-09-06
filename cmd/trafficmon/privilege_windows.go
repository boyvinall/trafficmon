//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// requirePrivileged checks that the process has the access packet capture
// and libproc need to see other users' sockets.
var requirePrivileged = func() error {
	token := windows.GetCurrentProcessToken()
	if !token.IsElevated() {
		return fmt.Errorf("must run as Administrator (right-click and choose 'Run as Administrator')")
	}
	return nil
}
