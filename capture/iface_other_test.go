//go:build !windows

package capture

import "testing"

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
