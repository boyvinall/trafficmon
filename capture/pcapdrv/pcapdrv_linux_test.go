//go:build linux

package pcapdrv

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

// resetLoadState lets each test exercise loadLibrary's sync.Once path fresh,
// restoring the package's real hooks/state afterwards.
func resetLoadState(t *testing.T) {
	t.Helper()
	origDlopen := dlopenFunc
	origDlsym := dlsymFunc
	t.Cleanup(func() {
		loadOnce = sync.Once{}
		loadErr = nil
		dlopenFunc = origDlopen
		dlsymFunc = origDlsym
	})
	loadOnce = sync.Once{}
	loadErr = nil
}

func TestLoadLibrary_LibraryNotFound(t *testing.T) {
	resetLoadState(t)

	dlopenFunc = func(name string) (unsafe.Pointer, error) {
		return nil, errors.New(name + ": cannot open shared object file: No such file or directory")
	}

	err := loadLibrary()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, ErrLibraryNotFound) {
		t.Fatalf("expected error to wrap ErrLibraryNotFound, got: %v", err)
	}

	msg := err.Error()
	for _, want := range []string{"apt install", "dnf install", "libpcap"} {
		if !strings.Contains(msg, want) {
			t.Errorf("expected error message to mention %q for actionable guidance, got: %s", want, msg)
		}
	}
}

func TestLoadLibrary_SymbolNotFound(t *testing.T) {
	resetLoadState(t)

	dummyHandle := unsafe.Pointer(&struct{}{})
	dlopenFunc = func(_ string) (unsafe.Pointer, error) {
		return dummyHandle, nil
	}
	dlsymFunc = func(_ unsafe.Pointer, symbol string) (unsafe.Pointer, error) {
		if symbol == "pcap_stats" {
			return nil, errors.New("undefined symbol: pcap_stats")
		}
		return unsafe.Pointer(&struct{}{}), nil
	}

	err := loadLibrary()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, ErrLibraryNotFound) {
		t.Fatalf("expected error to wrap ErrLibraryNotFound, got: %v", err)
	}

	msg := err.Error()
	if !strings.Contains(msg, "pcap_stats") {
		t.Errorf("expected error message to name the missing symbol, got: %s", msg)
	}
	if !strings.Contains(msg, "incompatible") && !strings.Contains(msg, "old") {
		t.Errorf("expected error message to explain the likely cause, got: %s", msg)
	}
}

func TestOpenLive_PropagatesLoadError(t *testing.T) {
	resetLoadState(t)

	dlopenFunc = func(_ string) (unsafe.Pointer, error) {
		return nil, errors.New("not found")
	}

	_, err := openLive("eth0", 1600, false, 0)
	if !errors.Is(err, ErrLibraryNotFound) {
		t.Fatalf("expected ErrLibraryNotFound from openLive, got: %v", err)
	}
}

func TestFindAllDevs_PropagatesLoadError(t *testing.T) {
	resetLoadState(t)

	dlopenFunc = func(_ string) (unsafe.Pointer, error) {
		return nil, errors.New("not found")
	}

	_, err := findAllDevs()
	if !errors.Is(err, ErrLibraryNotFound) {
		t.Fatalf("expected ErrLibraryNotFound from findAllDevs, got: %v", err)
	}
}
