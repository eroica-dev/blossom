# Progress Under Faults

This note states the progress assumptions for the verified path. The threshold
proof in `docs/proofs/thresholds.md` covers safety; this note covers when honest
nodes can eventually move forward.

## Assumptions

- Byzantine nodes remain within the verified-path bound
  `f = floor((n - 1) / 3)`.
- The network is eventually synchronous: before the stabilization point,
  messages may be late, dropped, fuzzed, or partitioned; after stabilization,
  messages among a supermajority of current validators are delivered within the
  configured timeout.
- A supermajority of current validators can serve either the certified epoch
  summary or the signed block/evidence needed to rebuild the lowest unresolved
  epoch.
- Honest nodes freeze progress at the lowest unresolved parent/nonce pair. They
  may hold speculative local state, but they do not build durable descendants
  until that nonce is reconciled.
- Reconnect and repair evidence is counted by distinct current identities and
  bound to the epoch, stage, body, and node identity being admitted.

## Progress Argument

If ordinary dispatch is timely, all honest nodes receive enough valid blocks to
derive the same epoch body and can advance directly.

If ordinary dispatch is not timely but the network is not permanently
partitioned, nodes enter repair. A node can adopt a summary only when that
summary is backed by the verified quorum for the exact epoch hash and nonce.
If summary repair cannot find a quorum, the node falls back to block-set
reconciliation. Once the network becomes synchronous, each honest recovering
node can gather the same signed block/evidence set from a supermajority of
current validators, rebuild the deterministic body, and adopt the reconciled
epoch.

If a partition lasts across multiple simulator ticks, the unresolved nonce stays
pending. Nodes do not form durable descendants for later nonces while the
pending epoch remains unreconciled. After the partition heals, reconciliation
for that same parent/nonce succeeds before ordinary block formation resumes.

If nodes are dropped and reconnected under Byzantine noise, progress continues
as long as the active network remains above the configured minimum and the
Byzantine population stays within the threshold. Dropped nodes rejoin only
after peer ping, catch-up proof, and admission vote quorums succeed; duplicate
or replayed Byzantine evidence can consume telemetry counters but cannot satisfy
the distinct-voter proof.

## Executable Coverage

- `partial_synchrony_progress_recovers_after_late_messages` injects deterministic
  latency spikes and verifies repair/reconciliation restores every epoch.
- `healed_full_partition_reconciles_pending_epoch_before_resuming` holds a full
  partition open for several simulator ticks, verifies no new block formation
  occurs while the prior nonce is pending, and then verifies reconciliation
  succeeds after the partition heals.
- `byzantine_churn_under_threshold_preserves_epoch_progress` combines Byzantine
  voters, duplicate admission votes, dropped nodes, reconnects, and latency
  spikes while staying under the Byzantine threshold.
- `check_runtime_reconciliation` now treats a divergent epoch as valid only if a
  later report for the same nonce and canonical hash shows full convergence, and
  the final active network is correct and single-hash.
