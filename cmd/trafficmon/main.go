// Command trafficmon is a netstat-style TUI joining live socket state with
// packet-capture bandwidth counters.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/urfave/cli/v3"
	"golang.org/x/sync/errgroup"

	"github.com/boyvinall/trafficmon/aggregate"
	"github.com/boyvinall/trafficmon/capture"
	"github.com/boyvinall/trafficmon/cmd/trafficmon/internal/tui"
	"github.com/boyvinall/trafficmon/dns"
	"github.com/boyvinall/trafficmon/procinfo"
)

var version = "dev"

func main() {
	app := &cli.Command{
		Name:    "trafficmon",
		Usage:   "live network bandwidth by process and destination",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "level",
				Aliases: []string{"l"},
				Value:   "info",
				Usage:   "log level (debug, info, warn, error)",
			},
			&cli.StringFlag{
				Name:    "iface",
				Aliases: []string{"i"},
				Usage:   "interface to capture on (default: the one backing the default route)",
			},
			&cli.BoolFlag{
				Name:  "include-loopback",
				Usage: "also capture loopback traffic",
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			level, err := parseLevel(cmd.String("level"))
			if err != nil {
				return ctx, err
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
			return ctx, nil
		},
		Action: run,
	}
	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// parseLevel parses the --level flag into a slog.Level, so that the
// parsing itself can be unit tested apart from the slog.SetDefault side
// effect that has to stay in the Before closure.
func parseLevel(s string) (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(s)); err != nil {
		return 0, fmt.Errorf("invalid log level %q: %w", s, err)
	}
	return level, nil
}

func run(ctx context.Context, cmd *cli.Command) error {
	// Both packet capture and libproc visibility into other users' processes
	// need elevated privileges: root on macOS/Linux (same as iftop/nettop),
	// Administrator on Windows.
	if err := requirePrivileged(); err != nil {
		return err
	}

	// Forces any pcap-open failure (most notably a missing libpcap on Linux)
	// to surface here and exit cleanly, rather than racing the TUI goroutine
	// that would otherwise be the first thing to open a handle.
	if _, err := capture.ListInterfaces(); err != nil {
		return fmt.Errorf("libpcap: %w", err)
	}

	iface := cmd.String("iface")
	if iface == "" {
		var err error
		if iface, err = capture.DefaultInterface(); err != nil { //nolint:contextcheck // DefaultInterface deliberately owns its own short, fixed timeout rather than ctx's
			return fmt.Errorf("detect interface: %w", err)
		}
	}
	slog.Info("starting capture", "iface", iface)

	cfg := capture.DefaultConfig()
	cfg.Interface = iface
	cfg.IncludeLoopback = cmd.Bool("include-loopback")

	capturer := capture.New(cfg)
	source := procinfo.NewBestSource()
	agg := aggregate.New(capturer, source)

	// The resolver needs no goroutine of its own: it starts one per lookup,
	// from the render loop, and bounds them itself.
	resolver := dns.NewResolver()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return capturer.Run(ctx) })
	g.Go(func() error { return source.Run(ctx) })
	g.Go(func() error {
		defer stop()
		p := tea.NewProgram(tui.NewModel(ctx, agg, resolver, capturer.HostnameCache(), iface), tea.WithAltScreen(), tea.WithContext(ctx))
		_, err := p.Run()
		return err
	})

	if err := g.Wait(); err != nil && !isShutdown(err) {
		return err
	}
	return nil
}

// isShutdown reports whether err is just the result of the program being wound
// up in an orderly way, rather than something the user needs to be told about.
//
// The comparisons have to be errors.Is rather than ==: bubbletea reports a
// cancelled external context as ErrProgramKilled wrapped around the context's
// own error, so an equality test would let the most ordinary termination there
// is — the user pressing q, which cancels the context capture and polling run
// under — through as a failure and print it on the way out.
//
// A render loop panic isn't distinguishable here: this bubbletea version
// recovers it internally, prints the stack trace, and returns a nil error
// from Run(), so it surfaces to the user only as that stack trace, not as a
// nonzero exit.
func isShutdown(err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, tea.ErrProgramKilled) ||
		errors.Is(err, tea.ErrInterrupted)
}
