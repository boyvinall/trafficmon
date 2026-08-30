package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestIsShutdown(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			// What quitting with q actually produces: the UI goroutine cancels
			// the shared context on its way out, and capture and polling both
			// return the cancellation.
			name: "cancelled context",
			err:  context.Canceled,
			want: true,
		},
		{
			// And what the UI goroutine produces if the cancellation reaches
			// it first — the wrapping is why an == comparison is not enough.
			name: "program killed by the context",
			err:  fmt.Errorf("%w: %w", tea.ErrProgramKilled, context.Canceled),
			want: true,
		},
		{
			name: "program killed",
			err:  tea.ErrProgramKilled,
			want: true,
		},
		{
			name: "interrupted",
			err:  tea.ErrInterrupted,
			want: true,
		},
		{
			name: "cancellation wrapped in context of its own",
			err:  fmt.Errorf("capture on en0: %w", context.Canceled),
			want: true,
		},
		{
			// A capture that never got off the ground has to be reported: it
			// is the difference between "you quit" and "you are not root".
			name: "capture failed to start",
			err:  errors.New("open en0: permission denied"),
			want: false,
		},
		{
			name: "the render loop panicked",
			err:  fmt.Errorf("%w: %w", tea.ErrProgramKilled, tea.ErrProgramPanic),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isShutdown(tc.err); got != tc.want {
				t.Errorf("isShutdown(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
