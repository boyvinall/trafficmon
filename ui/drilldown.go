package ui

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/boyvinall/mac-nethogs/aggregate"
)

// Mode is a top-level view.
type Mode uint8

// Top-level views, toggled with tab.
const (
	ModeProcess Mode = iota
	ModeDestination
)

// Frame is one entry on the drill-down stack: the view being shown plus the
// filter that scopes it.
//
// Everything a frame holds is fixed at the moment it is pushed: the filter
// closes over the identity of the row the user selected, and the label spells
// that same choice out. Nothing that happens to the view afterwards — the
// destination grouping being toggled, the process being renamed, the row
// ageing out entirely — can therefore change what an already-pushed frame
// means, or leave its breadcrumb describing a scope it no longer filters on.
type Frame struct {
	Mode  Mode
	Label string // breadcrumb text, e.g. "Process: Chrome (pid 4821)"

	// Scope names what this frame filters on, e.g. "pid:4821". It is empty on
	// the unfiltered bottom frame. Two frames sharing a scope apply the same
	// predicate, which is what lets the stack recognise a drill that could not
	// narrow anything.
	Scope string

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

// HasScope reports whether some frame already on the stack filters on scope.
//
// The filters are idempotent: a second FilterByProcess for the same PID
// removes nothing the first one did not, so drilling into a scope that is
// already on the stack would push a frame showing exactly the rows underneath
// it — and one the user then has to press esc twice to leave. Refusing that is
// what stops process → destination → process ping-ponging down an unbounded
// stack of identical views, while leaving genuine drilling, which narrows
// something every step, as deep as the data allows.
func (s *Stack) HasScope(scope string) bool {
	for _, f := range s.frames {
		if f.Scope != "" && f.Scope == scope {
			return true
		}
	}
	return false
}

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

// Breadcrumb renders the drill path for the header bar, e.g.
// "Process: Chrome (pid 4821) → Destinations".
//
// The bottom frame is the unfiltered top-level view, which the header already
// names via the mode label, so it carries no label and contributes nothing.
// That makes an empty result the signal for "not drilled in" and keeps the
// header from showing a redundant "By Process → " prefix at depth 0.
func (s *Stack) Breadcrumb() string {
	labels := make([]string, 0, len(s.frames)-1)
	for _, f := range s.frames[1:] {
		if f.Label != "" {
			labels = append(labels, f.Label)
		}
	}
	return strings.Join(labels, " → ")
}

// processFrame builds the drill-down from a by-process row into just that
// process's destinations.
//
// The label names only the scope. What the view it opens is a list of — the
// "→ Destinations" the plan's breadcrumb ends in — is composed by the header
// from the mode on top of the stack, so that a frame the user has since
// drilled past does not keep claiming to be the list they are looking at.
//
// The PID is copied out of the row and into the closure rather than the row
// being reached for when the filter runs, because the model's row slice is
// rebuilt from a fresh snapshot on every tick: a filter that read the
// selection back out of the model would follow whatever row later landed under
// the cursor instead of the one the user drilled into.
func processFrame(r aggregate.Row) Frame {
	pid := r.PID
	return Frame{
		Mode:   ModeDestination,
		Label:  fmt.Sprintf("Process: %s (pid %d)", r.Label, pid),
		Scope:  "pid:" + strconv.Itoa(int(pid)),
		Filter: func(s aggregate.Snapshot) aggregate.Snapshot { return aggregate.FilterByProcess(s, pid) },
	}
}

// destinationFrame builds the drill-down from a by-destination row into the
// processes talking to it.
//
// The grouping is read here and then frozen into the frame, because it decides
// both what the filter matches and what the breadcrumb claims it matches: a
// row selected as one specific port must keep meaning that port even after `g`
// has coarsened the view underneath it back to whole hosts.
func destinationFrame(r aggregate.Row, g aggregate.Grouping) Frame {
	addr, port := r.RemoteAddr, r.RemotePort
	withPort := g == aggregate.GroupByIPPort

	// net.JoinHostPort rather than a bare colon, so that an IPv6 destination
	// reads the same in the breadcrumb as it does in the table.
	label := addr
	if withPort {
		label = net.JoinHostPort(addr, strconv.Itoa(int(port)))
	}

	return Frame{
		Mode:  ModeProcess,
		Label: "Destination: " + label,
		Scope: "dst:" + label,
		Filter: func(s aggregate.Snapshot) aggregate.Snapshot {
			return aggregate.FilterByDestination(s, addr, port, withPort)
		},
	}
}
