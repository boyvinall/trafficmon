package ui

import (
	"fmt"
	"testing"

	"github.com/boyvinall/mac-nethogs/aggregate"
)

func TestStackBreadcrumb(t *testing.T) {
	tests := []struct {
		name   string
		frames []Frame
		want   string
	}{
		{
			// The bottom frame is the unfiltered top-level view, which the
			// header names via the mode label instead.
			name: "depth 0",
			want: "",
		},
		{
			name:   "depth 1",
			frames: []Frame{{Mode: ModeDestination, Label: "Process: Chrome (pid 4821)"}},
			want:   "Process: Chrome (pid 4821)",
		},
		{
			name: "depth 2",
			frames: []Frame{
				{Mode: ModeDestination, Label: "Process: Chrome (pid 4821)"},
				{Mode: ModeProcess, Label: "Destination: 140.82.112.3:443"},
			},
			want: "Process: Chrome (pid 4821) → Destination: 140.82.112.3:443",
		},
		{
			// A frame pushed without a label contributes nothing rather than
			// leaving a dangling separator.
			name: "unlabelled frame is skipped",
			frames: []Frame{
				{Mode: ModeDestination, Label: "Process: Chrome (pid 4821)"},
				{Mode: ModeProcess},
			},
			want: "Process: Chrome (pid 4821)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStack(ModeProcess)
			for _, f := range tc.frames {
				s.Push(f)
			}

			if got := s.Breadcrumb(); got != tc.want {
				t.Errorf("Breadcrumb() = %q, want %q", got, tc.want)
			}
			if got := s.Depth(); got != len(tc.frames) {
				t.Errorf("Depth() = %d, want %d", got, len(tc.frames))
			}
		})
	}
}

func TestStackBreadcrumbAfterPop(t *testing.T) {
	s := NewStack(ModeProcess)
	s.Push(Frame{Label: "Process: Chrome (pid 4821)"})
	s.Push(Frame{Label: "Destination: 140.82.112.3:443"})

	s.Pop()
	if got, want := s.Breadcrumb(), "Process: Chrome (pid 4821)"; got != want {
		t.Errorf("Breadcrumb() = %q, want %q", got, want)
	}

	s.Pop()
	if got := s.Breadcrumb(); got != "" {
		t.Errorf("Breadcrumb() = %q, want empty at the top level", got)
	}

	// The bottom frame is never popped, so the breadcrumb stays empty rather
	// than the stack underflowing.
	s.Pop()
	if got := s.Breadcrumb(); got != "" {
		t.Errorf("Breadcrumb() = %q, want empty", got)
	}
}

func TestStackHasScope(t *testing.T) {
	s := NewStack(ModeProcess)

	// The bottom frame filters nothing, so its empty scope must not match the
	// empty scope of a frame that was pushed without one.
	if s.HasScope("") || s.HasScope("pid:980") {
		t.Fatalf("a fresh stack carries no scope")
	}

	s.Push(Frame{Scope: "pid:980"})
	s.Push(Frame{Scope: "dst:140.82.112.3"})

	for _, scope := range []string{"pid:980", "dst:140.82.112.3"} {
		if !s.HasScope(scope) {
			t.Errorf("HasScope(%q) = false, want true", scope)
		}
	}
	if s.HasScope("pid:22") {
		t.Errorf("HasScope reports a scope that was never pushed")
	}

	s.Pop()
	if s.HasScope("dst:140.82.112.3") {
		t.Errorf("a popped frame still holds its scope")
	}
	if !s.HasScope("pid:980") {
		t.Errorf("popping dropped more than the top frame")
	}
}

func TestStackApplyComposesFiltersInPushOrder(t *testing.T) {
	// Apply's doc says it runs every filter innermost (most-recently pushed)
	// last, meaning each frame's filter has to see the output of the one
	// pushed before it, not the original snapshot. These two filters are
	// order-sensitive — the second only produces "second-saw-1" if it runs
	// after the first has already added its connection — so this proves the
	// composition order rather than just that both ran.
	s := NewStack(ModeProcess)
	s.Push(Frame{
		Filter: func(snap aggregate.Snapshot) aggregate.Snapshot {
			snap.Connections = append(snap.Connections, aggregate.ConnectionRecord{ProcessName: "first"})
			return snap
		},
	})
	s.Push(Frame{
		Filter: func(snap aggregate.Snapshot) aggregate.Snapshot {
			snap.Connections = append(snap.Connections, aggregate.ConnectionRecord{
				ProcessName: fmt.Sprintf("second-saw-%d", len(snap.Connections)),
			})
			return snap
		},
	})

	got := s.Apply(aggregate.Snapshot{})

	want := []string{"first", "second-saw-1"}
	if len(got.Connections) != len(want) {
		t.Fatalf("Apply produced %d connections, want %d: %v", len(got.Connections), len(want), got.Connections)
	}
	for i, name := range want {
		if got.Connections[i].ProcessName != name {
			t.Errorf("connection %d = %q, want %q", i, got.Connections[i].ProcessName, name)
		}
	}
}

func TestStackSetModeNoopOnceDrilled(t *testing.T) {
	s := NewStack(ModeProcess)

	s.Push(Frame{Mode: ModeDestination})
	if s.Depth() == 0 {
		t.Fatalf("Push did not increase depth")
	}

	s.SetMode(ModeDestination)

	// SetMode only ever touches the bottom frame, and only at depth 0; once
	// something has been pushed on top of it, drilling back down and toggling
	// mode again is Push's job, not SetMode's.
	if got := s.frames[0].Mode; got != ModeProcess {
		t.Errorf("SetMode changed the bottom frame at depth %d: got mode %d, want %d", s.Depth(), got, ModeProcess)
	}
}

func TestProcessFrame(t *testing.T) {
	f := processFrame(aggregate.Row{Key: "980", Label: "Google Chrome Helper", PID: 980})

	if f.Mode != ModeDestination {
		t.Errorf("a process drills into the destination view, got mode %d", f.Mode)
	}
	if want := "Process: Google Chrome Helper (pid 980)"; f.Label != want {
		t.Errorf("Label = %q, want %q", f.Label, want)
	}
	if want := "pid:980"; f.Scope != want {
		t.Errorf("Scope = %q, want %q", f.Scope, want)
	}

	got := f.Filter(testSnapshot())
	if len(got.Connections) != 1 || got.Connections[0].PID != 980 {
		t.Errorf("filter kept %d connections, want only pid 980's", len(got.Connections))
	}
}

func TestDestinationFrame(t *testing.T) {
	tests := []struct {
		name      string
		row       aggregate.Row
		grouping  aggregate.Grouping
		wantLabel string
		wantScope string
		wantConns int
	}{
		{
			// Grouped by IP the port is not part of what the user selected, so
			// every port of the host stays in scope.
			name:      "by ip",
			row:       aggregate.Row{Label: "140.82.112.3", RemoteAddr: "140.82.112.3"},
			grouping:  aggregate.GroupByIP,
			wantLabel: "Destination: 140.82.112.3",
			wantScope: "dst:140.82.112.3",
			wantConns: 2,
		},
		{
			name:      "by ip:port",
			row:       aggregate.Row{Label: "140.82.112.3:443", RemoteAddr: "140.82.112.3", RemotePort: 443},
			grouping:  aggregate.GroupByIPPort,
			wantLabel: "Destination: 140.82.112.3:443",
			wantScope: "dst:140.82.112.3:443",
			wantConns: 1,
		},
		{
			// An IPv6 destination is bracketed in the breadcrumb exactly as it
			// is in the table, rather than ending in an ambiguous run of
			// colons.
			name:      "ipv6 by ip:port",
			row:       aggregate.Row{Label: "[2606:4700:4700::1111]:53", RemoteAddr: "2606:4700:4700::1111", RemotePort: 53},
			grouping:  aggregate.GroupByIPPort,
			wantLabel: "Destination: [2606:4700:4700::1111]:53",
			wantScope: "dst:[2606:4700:4700::1111]:53",
			wantConns: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := destinationFrame(tc.row, tc.grouping)

			if f.Mode != ModeProcess {
				t.Errorf("a destination drills into the process view, got mode %d", f.Mode)
			}
			if f.Label != tc.wantLabel {
				t.Errorf("Label = %q, want %q", f.Label, tc.wantLabel)
			}
			if f.Scope != tc.wantScope {
				t.Errorf("Scope = %q, want %q", f.Scope, tc.wantScope)
			}
			if got := f.Filter(testSnapshot()); len(got.Connections) != tc.wantConns {
				t.Errorf("filter kept %d connections, want %d", len(got.Connections), tc.wantConns)
			}
		})
	}
}
