# trafficmon

A `netstat`-style TUI for macOS: every currently open connection — local and
remote address, protocol, owning process and PID, and (for TCP) the kernel's
connection state — whether or not it has carried any traffic. Bandwidth,
where capture has counters for it, is joined onto the same row.

Row existence for TCP/UDP comes from the kernel's live socket table, not from
packet capture: an idle SSH session shows up just as readily as a connection
pushing megabytes. Capture supplies the bandwidth numbers on top, and process
attribution needs no joining at all — a connection only exists in the first
place because it was enumerated on the PID that owns it. ICMP and ARP have no
socket to enumerate, so those rows come from capture alone and carry no PID.

## Requirements

- macOS
- Go 1.22+
- Xcode Command Line Tools (`xcode-select --install`) — the `procinfo` package
  uses cgo to bind `libproc`
- `libpcap` (ships with macOS)

## Build and run

```sh
make build
sudo ./bin/trafficmon
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
| `PgUp`/`Ctrl-B`, `PgDn`/`Ctrl-F` | Move a screenful |
| `Home`, `End`/`G` | Jump to first/last row |
| `g` | Cycle grouping: ungrouped → by PID → by process |
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
| `procinfo/` | cgo `libproc` bindings, periodic open-socket enumeration incl. TCP state |
| `aggregate/` | mutex-protected shared state, traffic join, per-grouping rollups |
| `dns/` | async reverse DNS with an aggressive cache |
| `cmd/trafficmon/internal/tui/` | Bubble Tea model, key bindings, table, styles |

`capture/`, `procinfo/`, `aggregate/` and `dns/` form the core engine library; `cmd/trafficmon` is the TUI binary built on top of it.

## Development

```sh
make help    # list targets
make all     # build, lint, test
```
