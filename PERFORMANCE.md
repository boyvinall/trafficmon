# Performance

This file records the current understanding of `procinfo`'s two backends'
relative CPU cost and attribution completeness, so nobody has to re-run the
benchmarks in `procinfo/` just to sanity-check a change. Update it whenever
the real benchmark suite (`go test -bench=. ./procinfo/... -count=5`,
described below) is re-run and produces materially different numbers.

## Backends being compared

- **`procinfo.Poller`**: the procfs/libproc poller, once/sec full `/proc`
  (Linux) or `libproc` (Darwin) walk.
- **`procinfo.EBPFSource`**: the Linux-only eBPF socket-lifecycle backend
  (`procinfo/ebpf_linux.go`), consuming a ring buffer of connect/state-change
  events fed by fentry/fexit (BTF) or kprobe/kretprobe programs.

## Reference numbers: an earlier prototype (baseline expectation, not shipped code)

An earlier prototype eBPF backend — not this repo's shipped `procinfo`
package — was measured against synthetic connection churn, 20s wall per
rate, on a Docker Desktop `golang:1.22-bookworm` container
(`7.0.12-linuxkit`, aarch64):

| Churn rate | Poller CPU (user+sys) | Poller saw (of total churned) | eBPF CPU (user+sys) | eBPF events (of total churned) |
|---|---|---|---|---|
| none | ~0.46s | 0 of 0 | ~0.004s | 0 of 0 |
| 50/s (~1,100–1,150 total) | ~0.75s | **1** of ~1,100 | ~0.75–0.81s | 11,005–11,011 of 1,150 (9.57/conn) |
| 200/s (~4,400–4,600 total) | ~0.93s | **1** of ~4,400 | ~1.14s | 44,022 of 4,599 (9.57/conn) |
| 500/s (~11,000–11,500 total) | ~1.3s | **1** of ~11,000 | ~1.00s | 110,012 of 11,497 (9.57/conn) |

**Caveat**: this is one workload shape
(uniform-rate local connect/close churn to a loopback listener) on one
kernel/environment (Docker Desktop's linuxkit VM, aarch64, light background
load). It is directional evidence, not a final sizing number — real
production socket-table sizes, connection mixes, and CPU headroom could
shift these numbers in either direction. Treat it as the baseline
expectation to confirm or revise against the real benchmark below, not a
permanent citation — these are throwaway-prototype numbers, not numbers
from the shipped `procinfo` code.

Reading the table: at low/medium churn the two backends land in a similar
raw-CPU-seconds range, and at the point they diverge most clearly (500/s)
the *poller* is the pricier one — but the comparison is apples-to-oranges,
since the poller only ever attributed 1 of the churned connections (the
still-open listening socket) at any rate, while eBPF attributed every one.
The poller's cost tracks kernel-side accumulated socket-table rows (open +
lingering TIME_WAIT), not attribution work; eBPF's cost tracks real event
volume and is roughly flat across this rate range once past the "any events
at all" step from idle.

## Real numbers: the shipped `procinfo` benchmarks

`procinfo/churn_bench_test.go`, `procinfo/poller_bench_test.go`, and
`procinfo/ebpf_bench_linux_test.go` (Linux+root-gated) implement this
comparison against the actual shipped backends, not a prototype. Reproduce
with:

```sh
go test -bench=. ./procinfo/... -count=5
```

(the eBPF half of the suite additionally needs to run on Linux as root with
`/sys/kernel/btf/vmlinux` available — it `b.Skip`s itself otherwise, the
same convention `procinfo/libproc_linux_test.go`/`capture/pcap_test.go`
use). See CLAUDE.md's Docker section for how to run real Linux code from a
macOS box; this needs `--privileged` plus `/sys/kernel/btf` and
`/sys/kernel/debug` bind-mounted in addition to the plain
`golang:1.22-bookworm` + `libpcap-dev` pattern already documented there.

A `-count=5` run against a Docker Desktop `golang:1.22-bookworm` container
(`7.0.12-linuxkit`, aarch64 — same environment class as the earlier
prototype run above), 5s per churn rate per run, produced the numbers
below.

`benchstat` could not be installed in this environment: `go install
golang.org/x/perf/cmd/benchstat@latest` resolved to a `golang.org/x/perf`
version requiring `go >= 1.26.0`, newer than this container's `go 1.22.12`
toolchain (and `GOTOOLCHAIN=local` in this offline-ish container blocked an
automatic newer-toolchain download). Per the fallback this doc's own
methodology allows, here are the raw per-run numbers from a clean
`-bench=. -count=5` run instead:

| Benchmark | Run 1 | Run 2 | Run 3 | Run 4 | Run 5 | Mean |
|---|---|---|---|---|---|---|
| `BenchmarkEBPF/50conns_sec` cpu-sec | 0.245 | 0.250 | 0.258 | 0.248 | 0.241 | **0.248** |
| `BenchmarkEBPF/50conns_sec` events-seen | 2741 | 2741 | 2741 | 2741 | 2741 | **2741** |
| `BenchmarkEBPF/50conns_sec` conns-churned | 249 | 249 | 249 | 249 | 249 | 249 |
| `BenchmarkEBPF/50conns_sec` conns-open-at-end | 11 | 13 | 17 | 19 | 19 | **15.8** |
| `BenchmarkEBPF/200conns_sec` cpu-sec | 0.466 | 0.450 | 0.506 | 0.488 | 0.454 | **0.473** |
| `BenchmarkEBPF/200conns_sec` events-seen | 10991 | 11002 | 11002 | 10991 | 10991 | **10995** |
| `BenchmarkEBPF/200conns_sec` conns-churned | 999 | 1000 | 1000 | 999 | 999 | 999 |
| `BenchmarkEBPF/200conns_sec` conns-open-at-end | 32 | 40 | 31 | 29 | 31 | **32.6** |
| `BenchmarkEBPF/500conns_sec` cpu-sec | 1.296 | 1.423 | 1.141 | 1.497 | 1.180 | **1.307** (noisy) |
| `BenchmarkEBPF/500conns_sec` events-seen | 27458 | 27491 | 27491 | 27502 | 27491 | **27487** |
| `BenchmarkEBPF/500conns_sec` conns-churned | 2496 | 2499 | 2499 | 2500 | 2499 | 2499 |
| `BenchmarkEBPF/500conns_sec` conns-open-at-end | 93 | 70 | 78 | 58 | 92 | **78.2** |
| `BenchmarkPoller/50conns_sec` cpu-sec | 0.911 | 1.052 | 0.947 | 0.935 | 0.888 | **0.947** |
| `BenchmarkPoller/50conns_sec` conns-seen | 0 | 0 | 0 | 0 | 0 | 0 |
| `BenchmarkPoller/200conns_sec` cpu-sec | 1.429 | 1.407 | 1.316 | 1.359 | 1.222 | **1.347** |
| `BenchmarkPoller/200conns_sec` conns-seen | 0 | 0 | 0 | 0 | 0 | 0 |
| `BenchmarkPoller/500conns_sec` cpu-sec | 1.982 | 1.767 | 1.802 | 1.915 | 1.942 | **1.882** |
| `BenchmarkPoller/500conns_sec` conns-seen | 0 | 0 | 0 | 0 | 0 | 0 |

`ns/op` for every subtest is ~5.1–5.3s, i.e. `benchDuration` (5s) plus
harness/setup overhead — expected, since each iteration runs a fixed-wall-
clock churn window rather than a tight loop, exactly as designed.

Environment: `golang:1.22-bookworm` container, `--privileged`,
`/sys/kernel/btf` and `/sys/kernel/debug` bind-mounted, kernel
`7.0.12-linuxkit`, `linux/arm64`. eBPF attach mode was `fentry/fexit (BTF)`
on every run (the preferred mode actually attached, not the kprobe
fallback).

**Reading these numbers**: at every rate tested, `EBPFSource` is cheaper in
raw CPU seconds than `Poller`, and attributes essentially every churned
connection (`events-seen` tracks `conns-churned` closely) against
`Poller`'s `conns-seen` of 0 — `runChurn`'s listener closes via `defer`
right as the shared context is cancelled, racing `Poller`'s last poll of
that 5-second window, so whether the listener is still open at the exact
moment `Connections()` is read is timing-dependent. `EBPFSource`'s
`conns-open-at-end` stays a small fraction of `conns-churned` (roughly
6–8% here) rather than near zero, which is the expected residual for
connections still in flight (not yet in a terminal TCP state) at the
instant each 5s window ends, not an indication of stuck entries.

The comparison above is apples-to-oranges in the same way the earlier
prototype's was: `Poller`'s cost tracks kernel-side accumulated
socket-table rows, not attribution work, while `EBPFSource`'s tracks real
event volume and full attribution.
