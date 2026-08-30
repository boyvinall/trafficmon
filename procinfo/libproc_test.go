//go:build darwin

package procinfo

import (
	"os"
	"testing"
)

// TestListPIDs is a smoke test for the cgo layer: if the libproc bindings link
// and the struct sizes are right, our own PID is in the list.
func TestListPIDs(t *testing.T) {
	pids, err := ListPIDs()
	if err != nil {
		t.Fatalf("ListPIDs: %v", err)
	}
	if len(pids) == 0 {
		t.Fatal("ListPIDs returned no PIDs")
	}

	self := int32(os.Getpid())
	for _, pid := range pids {
		if pid == self {
			return
		}
	}
	t.Fatalf("own pid %d not found among %d pids", self, len(pids))
}

func TestProcessName(t *testing.T) {
	name, err := ProcessName(int32(os.Getpid()))
	if err != nil {
		t.Fatalf("ProcessName: %v", err)
	}
	if name == "" {
		t.Fatal("ProcessName returned an empty name")
	}
	t.Logf("own process name: %q", name)
}
