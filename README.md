# mac-nethogs

A `nethogs`-style TUI for macOS: live network traffic grouped by **process** or
by **destination**, with drill-down between the two.

> **Status: scaffold.** The package structure, CLI and UI shell are in place;
> the capture, attribution and aggregation logic are stubbed. Grep for
> `TODO(milestone` to find what remains.

## Requirements

- macOS
- Go 1.25+
- Xcode Command Line Tools (`xcode-select --install`) — the `procinfo` package
  uses cgo to bind `libproc`
- `libpcap` (ships with macOS)

## Build and run

```sh
make build
sudo ./bin/mac-nethogs
```

Root is required for the same reasons `iftop` and `nettop` require it: opening
a live pcap handle, and reading other processes' socket fd info via `libproc`.

### Flags

| Flag | Description |
|------|-------------|
| `-i`, `--iface` | Interface to capture on (default: the one backing the default route) |
| `--include-loopback` | Also capture loopback traffic |
| `-l`, `--level` | Log level: `debug`, `info`, `warn`, `error` |

## Keys

| Key | Action |
|-----|--------|
| `↑`/`k`, `↓`/`j` | Move selection |
| `Tab` | Toggle mode (process ↔ destination) |
| `Enter` | Drill into the selected row |
| `Esc`/`Backspace` | Pop the drill-down stack |
| `g` | (destination mode) toggle IP-only ↔ IP:port |
| `s` | Cycle sort key |
| `r` | Sort by live rate vs cumulative total |
| `/` | Filter rows by substring of the process name, address or resolved hostname |
| `p` | Pause/resume live updates |
| `?` | Help overlay |
| `q` | Quit |

## Layout

| Package | Role |
|---------|------|
| `capture/` | gopacket/libpcap live capture, flow keys, rate windowing |
| `procinfo/` | cgo `libproc` bindings, periodic local-port → process poll |
| `aggregate/` | mutex-protected shared state, the port join, per-view rollups |
| `dns/` | async reverse DNS with an aggressive cache |
| `ui/` | Bubble Tea model, key bindings, table, drill-down stack, styles |

## Development

```sh
make help    # list targets
make all     # build, lint, test
```
