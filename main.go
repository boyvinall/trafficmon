package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/urfave/cli/v3"
	"golang.org/x/sync/errgroup"

	"github.com/boyvinall/mac-nethogs/aggregate"
	"github.com/boyvinall/mac-nethogs/capture"
	"github.com/boyvinall/mac-nethogs/procinfo"
	"github.com/boyvinall/mac-nethogs/ui"
)

var version = "dev"

func main() {
	app := &cli.Command{
		Name:    "mac-nethogs",
		Usage:   "live network bandwidth by process and destination, for macOS",
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
			var level slog.Level
			if err := level.UnmarshalText([]byte(cmd.String("level"))); err != nil {
				return ctx, fmt.Errorf("invalid log level %q: %w", cmd.String("level"), err)
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

func run(ctx context.Context, cmd *cli.Command) error {
	// Both packet capture and libproc visibility into other users' processes
	// need root, same as iftop/nettop.
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (try: sudo %s)", os.Args[0])
	}

	iface := cmd.String("iface")
	if iface == "" {
		var err error
		if iface, err = capture.DefaultInterface(); err != nil {
			return fmt.Errorf("detect interface: %w", err)
		}
	}
	slog.Info("starting capture", "iface", iface)

	cfg := capture.DefaultConfig()
	cfg.Interface = iface
	cfg.IncludeLoopback = cmd.Bool("include-loopback")

	capturer := capture.New(cfg)
	poller := procinfo.NewPoller()
	agg := aggregate.New(capturer, poller)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return capturer.Run(ctx) })
	g.Go(func() error { return poller.Run(ctx) })
	g.Go(func() error {
		defer stop()
		p := tea.NewProgram(ui.NewModel(agg, iface), tea.WithAltScreen(), tea.WithContext(ctx))
		_, err := p.Run()
		return err
	})

	if err := g.Wait(); err != nil && !isShutdown(err) {
		return err
	}
	return nil
}

// isShutdown reports whether err is just the result of the context being
// cancelled during an orderly quit.
func isShutdown(err error) bool {
	return err == context.Canceled || err == tea.ErrProgramKilled
}
