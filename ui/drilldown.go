package ui

import "github.com/boyvinall/mac-nethogs/aggregate"

// Mode is a top-level view.
type Mode uint8

// Top-level views, toggled with tab.
const (
	ModeProcess Mode = iota
	ModeDestination
)

// Frame is one entry on the drill-down stack: the view being shown plus the
// filter that scopes it.
type Frame struct {
	Mode  Mode
	Label string // breadcrumb text, e.g. "Process: Chrome (pid 4821)"

	// Filter narrows a snapshot to this frame's scope. nil at the top level.
	Filter func(aggregate.Snapshot) aggregate.Snapshot
}

// Stack is the drill-down history. The bottom frame is always the unfiltered
// top-level view; drilling pushes, esc pops.
type Stack struct {
	frames []Frame
}

// NewStack returns a stack holding a single unfiltered frame in mode m.
func NewStack(m Mode) *Stack {
	return &Stack{frames: []Frame{{Mode: m}}}
}

// Push drills into f.
func (s *Stack) Push(f Frame) { s.frames = append(s.frames, f) }

// Pop returns to the previous frame. The bottom frame is never popped.
func (s *Stack) Pop() {
	if len(s.frames) > 1 {
		s.frames = s.frames[:len(s.frames)-1]
	}
}

// Top returns the frame currently on screen.
func (s *Stack) Top() Frame { return s.frames[len(s.frames)-1] }

// Depth reports how many levels deep the user has drilled.
func (s *Stack) Depth() int { return len(s.frames) - 1 }

// SetMode replaces the top-level mode. Only meaningful at depth 0; drilling
// down and then toggling mode is handled by Push instead.
func (s *Stack) SetMode(m Mode) {
	if len(s.frames) == 1 {
		s.frames[0].Mode = m
	}
}

// Apply runs every filter on the stack, innermost last.
func (s *Stack) Apply(snap aggregate.Snapshot) aggregate.Snapshot {
	for _, f := range s.frames {
		if f.Filter != nil {
			snap = f.Filter(snap)
		}
	}
	return snap
}

// Breadcrumb renders the drill path for the header bar.
//
// TODO(milestone 6): join the frame labels with " → ".
func (s *Stack) Breadcrumb() string {
	if len(s.frames) == 1 {
		return ""
	}
	return s.Top().Label
}
