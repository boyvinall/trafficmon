package ui

import "testing"

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
