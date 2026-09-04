package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isShutdown(tc.err); got != tc.want {
				t.Errorf("isShutdown(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    slog.Level
		wantErr bool
	}{
		{name: "debug", in: "debug", want: slog.LevelDebug},
		{name: "info", in: "info", want: slog.LevelInfo},
		{name: "warn", in: "warn", want: slog.LevelWarn},
		{name: "error", in: "error", want: slog.LevelError},
		{name: "uppercase is accepted", in: "WARN", want: slog.LevelWarn},
		{name: "invalid level", in: "bogus", wantErr: true},
		{name: "empty string", in: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLevel(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseLevel(%q) = %v, nil, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseLevel(%q) returned unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseLevel(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
