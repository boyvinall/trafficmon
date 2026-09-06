# trafficmon

A `netstat`-style TUI for macOS and Linux: every currently open connection —
local and remote address, protocol, owning process and PID, and (for TCP) the
kernel's connection state — whether or not it has carried any traffic.
Bandwidth, where capture has counters for it, is joined onto the same row.

Row existence for TCP/UDP comes from the kernel's live socket table, not from
packet capture: an idle SSH session shows up just as readily as a connection
pushing megabytes. Capture supplies the bandwidth numbers on top, and process
attribution needs no joining at all — a connection only exists in the first
place because it was enumerated on the PID that owns it. ICMP and ARP have no
socket to enumerate, so those rows come from capture alone and carry no PID.

## Requirements

- macOS or Linux
- Go 1.22+
- On macOS: Xcode Command Line Tools (`xcode-select --install`) — the
  `procinfo` package uses cgo to bind `libproc`; `libpcap` ships with macOS
- On Linux: `libpcap-dev` (or your distro's equivalent); socket enumeration
  is pure Go, parsing `/proc` directly, so no cgo toolchain is needed there

## Build and run

```sh
make build
sudo ./bin/trafficmon
```

Root is required for the same reasons `iftop` and `nettop` require it: opening
a live pcap handle, and reading other processes' socket fd info (via `libproc`
on macOS, `/proc` on Linux).

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
| `procinfo/` | per-OS open-socket enumeration incl. TCP state (cgo `libproc` on macOS, `/proc` parsing on Linux) |
| `dpi/` | pluggable deep-packet inspection: TLS/QUIC ClientHello SNI, plus DNS-answer and DNS-query inspectors |
| `aggregate/` | mutex-protected shared state, traffic join, per-grouping rollups |
| `dns/` | async reverse DNS with an aggressive cache |
| `cmd/trafficmon/internal/tui/` | Bubble Tea model, key bindings, table, styles |
| `receiver/` | OpenTelemetry receiver wrapping the engine — metrics and logs, no TUI |
| `cmd/otel-collector/` | custom OTel Collector distribution bundling `receiver/` |

`capture/`, `procinfo/`, `dpi/`, `aggregate/` and `dns/` form the core engine
library, consumed by both the TUI binary (`cmd/trafficmon`) and the
OpenTelemetry receiver (`receiver/`).

## OpenTelemetry

`receiver/` exposes the same engine data as OTel metrics and logs instead of
a TUI: `trafficmon.network.io`, `trafficmon.dns.query.count`, and
`trafficmon.network.syn.count` metrics, plus DNS-query and SYN-attempt log
records (each SYN record carries a rolling attempt count for its exact
local/remote 4-tuple over the trailing 3 minutes).

`cmd/otel-collector/` builds a runnable Collector distribution around it:

```sh
make build-otel-collector          # regenerate + compile bin/trafficmon-otelcol
sudo bin/trafficmon-otelcol --config cmd/otel-collector/config.yaml
```

Or try the minimal example (trafficmon receiver → debug for logs, prometheus
for metrics on `localhost:9464`):

```sh
cmd/otel-collector/config/run.sh
```

## Development

```sh
make help                # list targets
make all                 # build both binaries, lint, test — every module
make build-otel-collector  # just the OTel Collector distribution
```
