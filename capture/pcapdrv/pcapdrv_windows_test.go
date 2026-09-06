//go:build windows

package pcapdrv

import (
	"testing"
	"time"
)

func TestFindAllDevsWindows(t *testing.T) {
	names, err := findAllDevs()
	if err != nil {
		// Npcap enumeration needs elevated privileges on some hosts; nothing
		// to assert against there.
		t.Skipf("findAllDevs() error = %v", err)
	}
	if names == nil {
		t.Fatal("findAllDevs() = nil slice, want a non-nil slice")
	}
}

func TestOpenLiveWindows(t *testing.T) {
	if testing.Short() {
		t.Skip("opens a live pcap handle")
	}

	names, err := findAllDevs()
	if err != nil || len(names) == 0 {
		t.Skipf("no capturable devices: %v", err)
	}

	h, err := openLive(names[0], 1600, false, time.Second)
	if err != nil {
		t.Skipf("openLive() error = %v (Npcap installed? running elevated?)", err)
	}
	defer h.Close()

	if _, err := h.Stats(); err != nil {
		t.Errorf("Stats() error = %v", err)
	}
}
