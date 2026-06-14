# Blossom Protocol Telemetry

Blossom runtime telemetry is a backend-neutral event stream emitted by the
protocol runtime. It is designed to be cheap enough for protocol-stage tracing
and structured enough for distributed analysis by `blossom-observer`.

## Event Shape

All runtime telemetry uses `TelemetryEvent` from `src/telemetry.rs`.

Each event includes:

- `schema_version`
- `kind`: `event`, `span_start`, or `span_end`
- `span_id` and optional `parent_span_id`
- `timestamp_micros`
- `node`
- `group_id`
- `stage`
- `event`
- optional epoch target: `last_epoch`, `nonce`, `round`
- optional `peer` and `message_kind`
- `outcome`, `error`, and free-form `fields`

Absent optional fields are omitted from JSON exports instead of being serialized
as `null`.

The current runtime emits balanced spans around:

- block submission
- local dispatch construction
- dispatch intake
- hot dispatch intake
- echo request/response/redispatch intake
- verification intake
- proposal intake
- commit intake
- epoch-started intake

Reconciliation is currently modeled in `blossom-sim`; concrete runtime
`Reconcile*` messages should emit the same span shape when they land.

## Export

`TelemetryHandle` lets embedders install any sink implementing `TelemetrySink`.
The default sink is a no-op.

`JsonlTcpTelemetrySink` exports line-delimited JSON telemetry to an observer
service. The sink is non-blocking on the protocol path: `record` enqueues into
a bounded channel, and a background exporter batches JSON serialization and TCP
writes. If the queue is full or disconnected, the sink drops the event and
increments `dropped_events`.

```rust
let sink = blossom::JsonlTcpTelemetrySink::connect("127.0.0.1:7717")?;
config.telemetry = blossom::TelemetryHandle::new(std::sync::Arc::new(sink));
```

The default exporter queue holds 65,536 events and writes batches up to 1,024
events or 1 MiB, with a 50 us maximum batch delay and 10 ms maximum flush
delay. Embedders that need different tradeoffs can use
`JsonlTcpTelemetrySink::connect_with_config`.

The `blossom-node` binary exposes this as:

```bash
blossom-node --observer-addr 127.0.0.1:7717
```

or:

```bash
BLOSSOM_OBSERVER_ADDR=127.0.0.1:7717 blossom-node
```

## Observer

`blossom-observer` is the collector and analyzer crate.

Run the service:

```bash
cargo run -p blossom-observer --bin blossom-observer -- serve \
  --bind 127.0.0.1:7717 \
  --ui-bind 127.0.0.1:7718 \
  --output telemetry.jsonl
```

It accepts JSONL telemetry from multiple nodes over TCP and serves a live
dashboard at `http://127.0.0.1:7718` by default. The dashboard shows network
health, span balance, stage latency, and node-level health with per-stage
timings for each node. Use `--no-ui` to run the collector without the dashboard.

When `--output` is enabled, captured JSONL is buffered and written in batches so
file persistence does not dominate the collector path. On shutdown, it prints a
full analysis sweep as JSON: total events, span starts/ends, incomplete spans,
orphan span ends, error counts, stage counts, per-node event counts, node-level
errors/gaps, error counts by stage, and span duration summaries.

Span duration matching uses `(node, group_id, span_id)` because span IDs are
node-local. This lets every node count spans independently while the observer
still reconstructs durations correctly after central collection.

Analyze an offline JSONL capture:

```bash
cargo run -p blossom-observer --bin blossom-observer -- analyze --input telemetry.jsonl
```

`blossom-sim-epoch-chaos` streams modeled per-node stage spans to the same
observer while the simulation is running. Stage starts are emitted before the
modeled stage work and stage ends are emitted immediately after the stage
checkpoint is recorded:

The simulator keeps the per-node spans deliberately light: start/end spans carry
the stage, event, node, group, target, and round needed for duration analysis.
Rich checkpoint fields such as correctness counts, block counts, repair totals,
and message totals are emitted once per checkpoint as a `*_metrics` event. This
preserves per-node timing visibility without duplicating the same metric payload
across every node span.

Epoch chaos can also model faulty-node removal. Use `--faulty-nodes`,
`--drop-faulty-after-epochs`, `--max-dropped-nodes-per-epoch`, and
`--min-active-nodes` to shrink the active verifier set during a run. Stage and
epoch logs report active `nodes` plus cumulative `dropped_nodes`, and the
simulator emits a `membership_pruning/node_dropped` telemetry event with
`outcome=dropped` for each removed node. `blossom-observer` surfaces those nodes
with a dropped status in the dashboard and includes dropped-node counts in its
analysis JSON.

Dropped-node reconnection is modeled as the same kind of membership admission
process that normal joins should use. Enable it with
`--reconnect-dropped-after-epochs` and tune the two admission gates with
`--reconnect-ping-fanout`, `--reconnect-ping-quorum`,
`--reconnect-approval-quorum`, `--reconnect-timeout-ms`, and
`--max-reconnected-nodes-per-epoch`. A candidate first emits
`membership_reconnect/peer_ping` traffic to prove it can reach enough active
peers. If that ping quorum succeeds, the candidate must gather a
`membership_reconnect/catchup_proof` quorum for the current canonical checkpoint
before any admission vote is accepted. Only then does the active set run
`membership_reconnect/admission_vote`; only candidates with enough delivered
approvals rejoin the active set. Successful joins emit
`membership_reconnect/node_reconnected` with `outcome=reconnected`, including
the ping response count, catch-up proof count, and approval count.

The production/runtime boundary for this lifecycle is documented in
[`docs/node-lifecycle.md`](node-lifecycle.md): plain address-book registration is
reachability metadata, signed public-node admission is committed through
validator supermajorities, and dropped-node reconnect still needs production
catch-up proof wiring before public trustless deployment.

Runtime counters on the TCP and JSONL export hot paths use `fast-telemetry`
`0.5.1` sharded counters. Blossom still emits its stable JSONL event schema to
the observer, but local request/error/drop accounting no longer relies on one
shared atomic per counter.

The simulator now makes the trusted/trustless split explicit. Trusted mode is
for operational environments where nodes may be faulty, partitioned, or stale,
but are not intentionally Byzantine; it permits smaller repair-oriented
quorums and rejects the Byzantine attack knobs. Verified mode is the trustless
path. It rejects Byzantine populations beyond the BFT bound, requires repair
and reconnect quorums to meet Byzantine-safe supermajorities, and only prunes
faulty nodes when a supermajority of currently canonical active peers can back
the drop evidence. Under the `f < n/3` bound, that evidence set still contains
honest support even if Byzantine peers vote. Under heavy divergence, verified
mode may wait for reconciliation before dropping or reconnecting nodes.

The sim can also assign a deterministic-random Byzantine set with
`--byzantine-nodes`. These nodes are separate from `--faulty-nodes`: faulty
nodes model detectable bad epoch behavior that can be pruned, while Byzantine
nodes model adversarial membership behavior. The current Byzantine behaviors
are replaying stale reconnect evidence with `--byzantine-reconnect-replay-ppm`
presenting stale catch-up proofs with
`--byzantine-reconnect-stale-proof-ppm`, attempting to reconnect under a
different identity with `--byzantine-reconnect-sybil-ppm`, and sending duplicate
admission votes with `--byzantine-duplicate-vote-copies`. Reconnect admission
only counts current-epoch state evidence, binds the reconnect to the dropped
node's original key, and deduplicates votes by node identity, so replayed
evidence, stale proofs, Sybil attempts, and duplicate votes increase telemetry
counters without increasing the admission proof count.

Partition behavior can be injected with `--partition-start-epoch`,
`--partition-end-epoch`, and `--partition-left-nodes`. For reconnect-specific
admission split testing, `--partition-reconnect-only` partitions the ping,
catch-up proof, and vote paths while leaving the rest of consensus able to
maintain a checkpoint. This verifies that a dropped node cannot reconnect to one
side of a split unless that side can satisfy the full reconnect quorum; after
the partition window ends, the node can reconnect with a fresh checkpoint proof.

The practical safety assumption is the standard BFT bound: with `n` validators,
the network should treat `floor((n - 1) / 3)` Byzantine nodes as the maximum
tolerated set. The sim reports `max_byzantine_nodes_for_safety` and
`byzantine_tolerance_exceeded` in summary output for valid runs. Reconnect ping
and approval quorums must exceed the possible Byzantine responder/voter count
and, in verified mode, meet the supermajority threshold so a Byzantine minority
cannot admit a node by itself. The threshold proof and executable boundary tests
are tracked in `docs/proofs/thresholds.md`.

The reconnect vulnerability checklist is now executable in `blossom-sim`:
Byzantine active peers cannot approve a stale node without a catch-up proof;
old ping/admission evidence is rejected as replay; duplicate votes are counted
once per peer identity; reconnect-side partitions block admission until merge;
drop and reconnect can happen in the same epoch under load; many dropped nodes
are rate-limited by `--max-reconnected-nodes-per-epoch`; unsafe low and
impossible high quorums fail validation; catch-up proof is required before
admission; and reconnect remains bound to the dropped node's original key.
The progress checklist is also executable: partial synchrony with late messages
is repaired, full partitions freeze the unresolved nonce until heal, and
Byzantine churn below the threshold preserves final convergence. The proof
obligations are summarized in `docs/proofs/progress.md`.

Sub-quorum dispatch also reports block-level data flow, separate from
message-level transport. `block_transfer_attempts` counts block payloads offered
inside delivered dispatch messages. `accepted_blocks` and
`accepted_block_bytes` count blocks whose `last_epoch` and `nonce` match the
recipient's expected epoch target. `denied_blocks` and `denied_block_bytes`
count blocks carried through a delivered sub-quorum message but rejected by the
recipient. This makes bad quorum placement visible: a faulty node can spend
bandwidth offering its block, but correct peers deny it instead of merging it.

```bash
OBSERVER_ADDR=127.0.0.1:7717 ./benchmarks/scripts/run-epoch-chaos.sh
```

For a focused telemetry overhead check, run the epoch chaos workload in paired
baseline and telemetry modes:

```bash
cargo run -p blossom-sim --bin blossom-sim-epoch-chaos -- \
  --nodes 36 \
  --epochs 48 \
  --repair-rounds 5 \
  --measure-telemetry-cost \
  --telemetry-cost-runs 3
```

Without `--observer-addr`, the telemetry side uses an in-memory sink and
measures instrumentation plus local collection overhead. With `--observer-addr`,
the telemetry side streams JSONL to `blossom-observer` and includes
enqueue, background serialization, TCP write, and shutdown flush cost.

## Next Runtime Work

- Add telemetry spans to concrete reconciliation messages once
  `ReconcileAppraisal`, `ReconcileRequest`, `ReconcileResponse`, and
  `ReconcileCommit` are implemented.
- Add parent span IDs for whole-epoch spans so per-message spans can be grouped
  under one epoch attempt.
- Add observer analyses for quorum progress, missing spans by node/stage, and
  finality proof completeness.
