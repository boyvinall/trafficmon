# trafficmon Receiver

The trafficmon receiver wraps the same engine that backs the [`trafficmon`
TUI](../README.md) — live packet capture joined with the kernel's open-socket
table — and exposes it as OpenTelemetry metrics and logs instead of rows on a
screen: per-connection byte counters, outbound DNS queries, and outbound TCP
SYNs (connection attempts).

| Status        |                                          |
| ------------- | ---------------------------------------- |
| Stability     | [development]: metrics, logs              |
| Distributions | [cmd/otel-collector](../cmd/otel-collector) |

[development]: https://github.com/open-telemetry/opentelemetry-collector/blob/main/docs/component-stability.md#development

## Getting Started

```yaml
trafficmon:
  collection_interval: <duration> # default = 1s
  interface: <string>             # default = auto-detect from the default route
  include_loopback: <bool>        # default = false
  max_peer_cardinality: <int>     # default = 1000
```

- `collection_interval`: how often the receiver polls the engine (capture +
  procinfo) for a fresh snapshot and emits it as metrics/logs.
- `interface`: the network interface to capture on. Empty auto-detects the
  interface backing the default route, the same as `cmd/trafficmon`.
- `include_loopback`: also captures loopback traffic.
- `max_peer_cardinality`: see [Cardinality](#cardinality) below.

Capturing packets and reading other processes' socket info both need root,
the same as `cmd/trafficmon` — see the [repo README](../README.md) for why.

## Metrics

All three metrics are namespaced `trafficmon.*`, since none of them are
standard semconv metrics, and are cumulative monotonic sums — derive a rate
with `rate()`/delta in your backend of choice.

| Metric | Unit | Attributes | Description |
| ------ | ---- | ---------- | ----------- |
| `trafficmon.network.io` | `By` | `network.io.direction` (`transmit`\|`receive`), `network.transport` (`tcp`\|`udp`), `network.interface.name`, `network.peer.address`, `network.peer.port`, `process.pid`, `process.executable.name` | Bytes transferred per connection, split by direction |
| `trafficmon.dns.query.count` | `{query}` | `dns.question.name`, `dns.question.type` | Outbound DNS queries observed, per question name and record type |
| `trafficmon.network.syn.count` | `{attempt}` | `network.peer.address`, `network.peer.port`, `network.interface.name` | Outbound TCP SYNs (connection attempts) observed, per remote endpoint |

Attribute keys follow [semantic conventions](https://opentelemetry.io/docs/specs/semconv/)
where a matching one exists (`network.peer.address`, `network.peer.port`,
`network.interface.name`, `network.transport`, `process.pid`,
`process.executable.name`); the rest are receiver-specific.

## Logs

- **DNS query**: one log record per outbound question, body = the query
  name. Attributes: `dns.question.name`, `dns.question.type`,
  `network.peer.address` (the resolver), and `network.local.address` (the
  querying process' local address) when the receiver can attribute it to a
  currently-open connection. That attribution is inherently best-effort: it
  depends on procinfo's once-a-second socket poll catching the query's
  outbound socket while it's still open, so a short-lived query can easily
  go unattributed.
- **SYN attempt**: one log record per SYN seen with no ACK set (i.e. the
  opening packet of a new connection, not one already established).
  Attributes: `network.peer.address`, `network.peer.port`,
  `network.interface.name`, `network.local.port`, and
  `network.syn.attempt_count` — how many SYNs this exact local↔remote
  4-tuple has produced within the trailing 3 minutes, from an in-memory
  rolling cache the receiver keeps for this purpose alone. There is no PID
  attribution for a SYN observation: it comes from capture alone, the same
  as this repo's ICMP/ARP rows.

## Cardinality

Per-flow and per-SYN attribution is naturally high-cardinality — nothing in
the underlying engine bounds the number of distinct remote endpoints it will
report on. `max_peer_cardinality` caps how many distinct
`(remote address, port)` pairs may carry their own attributes within one
collection interval; past the cap, further `trafficmon.network.io`/
`trafficmon.network.syn.count` data points for that interval fold into a
single overflow series carrying `network.peer.address.overflow="true"`
instead of their own remote address/port.

## Example

```yaml
receivers:
  trafficmon:
    collection_interval: 1s

exporters:
  prometheus:
    endpoint: localhost:9464
  debug:
    verbosity: detailed

service:
  pipelines:
    metrics:
      receivers: [trafficmon]
      exporters: [prometheus]
    logs:
      receivers: [trafficmon]
      exporters: [debug]
```

See [`cmd/otel-collector`](../cmd/otel-collector) for a full, runnable
Collector distribution bundling this receiver, and
[`cmd/otel-collector/config/example.yaml`](../cmd/otel-collector/config/example.yaml)
for exactly this config plus a script to run it.
