# Trusted Checkpoint-DAG Experiment

`trusted-checkpoint-dag` evaluates an append-only dissemination layer beneath
Blossom's existing trusted sequential quorum ordering. It is not an alternate
consensus protocol and has no production wire integration.

The experiment preserves these ordering boundaries:

1. Every writer appends an immutable vertex to its own origin hash chain.
2. A round candidate is a compact full frontier over those chains.
3. Acknowledgements for one member may only advance that frontier.
4. A member durably locks at most one candidate after its selected round quorum
   reaches the trusted two-thirds threshold.
5. A round advances only after the same threshold confirms that candidate.
6. Every later hierarchical round must carry the previous confirmed frontier.
7. Only the final topology round appends a linear checkpoint containing the
   previous checkpoint hash and nonce.

The production-shaped state machine requires at least six logical Global
Blossom members and at least the configured branching factor. With the default
`q=6`, six is the first valid Global Blossom population. Small trusted clusters
remain HA's scope.

HA and Global Blossom are parallel networks. An HA group does not collapse
into one Blossom voter, and its replicas do not receive votes in Blossom
implicitly. The `parallel-networks` composition feature only places immutable
HA registration and sealed-state references into the global DAG as application
records.

Vertices contain one origin-parent reference rather than one parent reference
per validator. The sequential quorum candidate binds the complete frontier and
therefore remains the source of universal order.

The model uses a stable topological merge for a finalized checkpoint. An
origin's vertices remain in sequence order. Concurrently eligible origin heads
are ordered by vertex hash and then origin identity, matching trusted-direct's
block-hash ordering when every writer contributes one vertex.

## Scale experiment

```sh
cargo run --release \
  --features trusted-checkpoint-dag \
  --bin blossom-trusted-dag-experiment -- \
  --nodes 6,72,256,1000 \
  --quorum-size 6 \
  --payload-bytes 1024
```

The report distinguishes:

- The unavoidable logical `N × N` payload-delivery bytes when every node must
  eventually possess every writer payload.
- Materialized payload bytes that would be carried repeatedly through
  sequential hierarchy levels.
- Hash-reference bytes for the same hierarchy.
- Compact bitmap/frontier plus digest control bytes.
- Topology construction and sequential frontier-reduction time.

These are logical architecture measurements, not TCP throughput claims.

The first deterministic release run used one 1,024-byte vertex per writer:

| Nodes | `q` | Rounds | Candidate occurrences | Hash-reference path | Compact frontier path |
|---:|---:|---:|---:|---:|---:|
| 1,000 | 3 | 6 | 1,552,206 | 49.67 MB | 1.92 MB |
| 1,000 | 6 | 4 | 1,317,064 | 42.15 MB | 1.28 MB |
| 1,000 | 9 | 3 | 1,137,288 | 36.39 MB | 0.96 MB |
| 1,000 | 12 | 3 | 1,197,312 | 38.31 MB | 0.96 MB |
| 1,000 | 18 | 3 | 1,352,784 | 43.29 MB | 0.96 MB |
| 2,000 | 3 | 7 | 7,254,436 | 232.14 MB | 8.06 MB |
| 2,000 | 6 | 4 | 4,869,976 | 155.84 MB | 4.61 MB |
| 2,000 | 9 | 4 | 6,423,028 | 205.54 MB | 4.61 MB |
| 2,000 | 12 | 3 | 4,394,784 | 140.63 MB | 3.46 MB |
| 2,000 | 18 | 3 | 4,707,264 | 150.63 MB | 3.46 MB |

All rows converged to one full frontier. The best branching factor depends on
the physical population and its tensor shape: `q=9` minimized candidate
occurrences at 1,000 nodes, while `q=12` did so at 2,000. The implementation
must therefore report topology shape and should not assume one globally optimal
`q`.

## Safety and recovery model

The feature tests:

- Parent-before-child and child-before-parent arrival.
- Conflicting bytes at one origin sequence.
- Monotonic acknowledgements.
- Immutable confirmation locks and Borsh restart recovery.
- Two-thirds acknowledgement and confirmation thresholds.
- Sequential carry-forward across hierarchy levels.
- Late vertices entering later checkpoints without retargeting.
- Deterministic topological order.
- The real quorum-selection topology at 6, 72, and 1,000 nodes.
- A 1,001-checkpoint rotating-omission soak.

The experiment does not modify verified Blossom, trusted-direct epoch encoding,
the production trusted LogStore schema, HA, snapshots, handshakes, or wire message
codes. Production integration requires a separate gate for durable vertex
storage, authenticated frontier messages, catch-up, garbage collection, and
fault-injected multi-process benchmarks.
