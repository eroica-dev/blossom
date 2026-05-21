# Subset Block Gossip Propagation Proof

This note documents the optimized recipient-filtered block propagation model and
the simulated test cases used to validate it. The goal of subset block gossip is
to reduce data-plane duplication while preserving the consensus object: every
validator commits the same block metadata and block hashes, while only command
targets receive the full command payload bytes.

The latest optimized validation run is:

```text
EPOCHS=50 REPEAT_RUNS=3 benchmarks/scripts/run-subset-gossip-matrix.sh
```

Result directory:

```text
benchmarks/results/subset_gossip_20260521_051925
```

## Protocol Versions

The simulator keeps two stable protocol profiles so optimization work can be
compared without mutating the baseline:

- `v1`: the original recipient-filtered subset gossip path. It starts consensus
  at round 0, uses no prefill dispatch, and relies on repair to fill missing
  target payloads.
- `v2`: the prefill-dispatch path. It performs one deterministic prefill stage
  to future quorum contacts, skips exactly one consensus wave, and disables
  repair by default so missing-data regressions are visible.

Low-level experiments that change the propagation shape, such as random prefill,
scheduled prefill, hash advertisement, or unsafe fanout overrides, are labeled
`custom`. The benchmark CLI exposes the profile through
`--protocol-version v1|v2|custom`, and `SubsetGossipConfig::for_protocol_version`
provides the same presets in code.

## Model

Each command is represented by a filtered transaction slot:

```text
slot = {
  command key hash,
  command kind,
  target server identities,
  payload commitment,
  payload length,
  delivery policy
}
```

The block hash commits to this slot metadata. Full-payload and tombstone views
therefore share the same canonical block hash, which lets consensus proceed over
metadata even when payload bytes are recipient-filtered.

For each dispatch from `sender` to `recipient`, the model does:

```text
for block in sender.known_blocks:
  include canonical block metadata

  full_payloads = sender.full_payloads(block) intersect block.targets(recipient)
  if full_payloads is non-empty:
    include those payload bytes for recipient
  else:
    include the tombstone/commitment view
```

On receipt, the recipient state is updated as:

```text
recipient.metadata = recipient.metadata union block.metadata
recipient.full_payloads(block) =
  recipient.full_payloads(block) union (sender.full_payloads(block) intersect block.targets(recipient))
```

The optimized simulator implements this as a direct bitmask merge:

```text
R' = R union (S intersect T)
```

where `R` is the recipient's known full-payload mask for a block, `S` is the
sender's known full-payload mask, and `T` is the target mask for the recipient.
This is equivalent to materializing the intersection and then merging it, but it
avoids per-delivery allocation in the bench model.

## Correctness Conditions

The simulation treats a propagated epoch as correct when all of these hold:

1. Every node knows every canonical block metadata entry for the epoch.
2. Every command target holds the full payload for that command.
3. Missing target payloads after repair are zero.
4. The recipient-filtered wire model never requires more bytes than the full
   replication model for the same epoch.

Metadata convergence alone is not sufficient. A node can know a command's hash,
target set, commitment, and payload length while still missing the payload bytes
it must execute. The proof and tests therefore track both metadata convergence
and target payload completeness.

## Repair Rule

Inline subset propagation can miss target payloads when a target learns metadata
from peers that only hold tombstones. The model closes that gap with a pull
repair phase:

```text
for block in canonical_blocks:
  for target in block.command_targets:
    missing = target.required_payloads(block) - target.full_payloads(block)
    if missing is non-empty:
      target sends a batch fetch to the original holder
      holder returns filtered payload delivery for missing slots
      target marks those slots full
```

Under the simulation assumptions, the original holder remains available and
serves the committed payload slots. This makes the repair proof simple:

```text
missing_after_repair =
  required_target_payloads - (delivered_inline union repaired_from_holder)
```

For each missing slot, the repair step requests that exact slot from a holder
that started with the full local block. After delivery, that slot is inserted
into the target's full-payload mask. Therefore every repaired slot is removed
from the missing set, and no non-target payload is required for correctness.

The known boundary is also explicit: without repair, sparse target sets are not
always complete. The tests intentionally observe missing payloads before repair
for target counts 3 and 6, then require zero missing payloads after repair.

## Optimized Simulator Soundness

The optimization pass changed simulator internals, not the propagation metrics.
The key equivalences are:

- Direct mask merge computes `R union (S intersect T)`, the same state as
  constructing an intermediate payload mask and merging it.
- The target selector now uses a small sorted vector instead of a `BTreeSet`.
  It still preserves uniqueness, includes the owner, and sorts the final target
  set before metadata construction.
- Payload commitments are still generated from the same deterministic byte
  stream; the simulator batches hasher updates in 64-byte chunks.
- Control-message accounting uses modeled headers with fixed-size signatures.
  This preserves encoded frame lengths for propagation benchmarking while
  avoiding real signing work in the length model. Real signing and verification
  are still covered by the protocol unit and TCP e2e tests.

The representative 64-node verified workload validated that the optimized run
preserved output exactly:

```text
nodes=64 quorum_size=6 epochs=50 commands_per_node=256 command_bytes=1024 targets=3
before: real 7.64s, user 7.60s
after:  real 6.79s, user 6.50s
CSV output: byte-for-byte identical
```

The optimized aggregate matrix is also byte-for-byte identical to the previous
post-allocation-optimization aggregate CSV.

## Simulated Test Matrix

The matrix runs the same workloads for trusted and verified architectures:

| Dimension | Values |
|---|---|
| Architectures | trusted, verified |
| Latency profiles | even 150 ms, random 1-300 ms |
| Node counts | 12, 36, 64 |
| Targets per command | 1, 3, 6 |
| Commands per node per epoch | 256 |
| Command payload bytes | 1024 |
| Repeats per scenario | 3 |
| Epochs per run | 50 |

This is `2 x 2 x 3 x 3 x 3 = 108` run groups and `5400` modeled epochs.

Observed correctness summary:

| Metric | Result |
|---|---:|
| Run groups | 108 |
| Aggregate groups | 36 |
| Modeled epochs | 5400 |
| Metadata-converged epochs | 5400 |
| Payload-complete epochs after repair | 5400 |
| Missing payloads after repair | 0 |
| Highest missing-before-repair case | 52.61% |

The highest missing-before-repair case was
`trusted/even150/n=36/targets=6/repeat=1`. This is expected: it is not a
post-repair failure; it demonstrates that inline subset propagation alone is not
a complete availability proof.

## Even-Latency Results

Even-latency runs use 150 ms per network hop.

| Arch | Nodes | Targets | Wire savings | Missing before repair | Missing after repair | Payload-ready ms | TPS | Per-node Gb/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| trusted | 12 | 1 | 87.200% | 0.0000% | 0 | 600.00 | 5120.00 | 0.017958 |
| trusted | 12 | 3 | 75.409% | 12.7216% | 0 | 900.00 | 3413.33 | 0.024253 |
| trusted | 12 | 6 | 54.928% | 3.7842% | 0 | 900.00 | 3413.33 | 0.047898 |
| trusted | 36 | 1 | 87.200% | 0.0000% | 0 | 1800.00 | 5120.00 | 0.005986 |
| trusted | 36 | 3 | 77.026% | 46.2401% | 0 | 2100.00 | 4388.57 | 0.009711 |
| trusted | 36 | 6 | 63.217% | 52.5591% | 0 | 2100.00 | 4388.57 | 0.016753 |
| trusted | 64 | 1 | 87.207% | 0.0000% | 0 | 1800.00 | 9102.22 | 0.020147 |
| trusted | 64 | 3 | 80.963% | 45.2527% | 0 | 2100.00 | 7801.90 | 0.027097 |
| trusted | 64 | 6 | 72.584% | 51.5417% | 0 | 2100.00 | 7801.90 | 0.042050 |
| verified | 12 | 1 | 86.984% | 0.0000% | 0 | 3000.00 | 1024.00 | 0.003661 |
| verified | 12 | 3 | 75.232% | 12.7216% | 0 | 3300.00 | 930.91 | 0.006678 |
| verified | 12 | 6 | 54.809% | 3.7842% | 0 | 3300.00 | 930.91 | 0.013126 |
| verified | 36 | 1 | 86.889% | 0.0000% | 0 | 9000.00 | 1024.00 | 0.001231 |
| verified | 36 | 3 | 76.766% | 46.2401% | 0 | 9300.00 | 990.97 | 0.002225 |
| verified | 36 | 6 | 63.019% | 52.5591% | 0 | 9300.00 | 990.97 | 0.003815 |
| verified | 64 | 1 | 86.890% | 0.0000% | 0 | 9000.00 | 1820.44 | 0.004144 |
| verified | 64 | 3 | 80.684% | 45.2527% | 0 | 9300.00 | 1761.72 | 0.006230 |
| verified | 64 | 6 | 72.352% | 51.5417% | 0 | 9300.00 | 1761.72 | 0.009606 |

## Random-Latency 64-Node Results

Random-latency runs sample per-edge latency from 1-300 ms. The table reports
means across three repeats with 95% confidence intervals from the analyzer.

| Arch | Nodes | Targets | Ready ms +/- 95% CI | TPS +/- 95% CI | Savings +/- 95% CI |
|---|---:|---:|---:|---:|---:|
| trusted | 64 | 1 | 2390.67 +/- 75.41 | 6854.06 +/- 216.91 | 87.207% +/- 0.000 |
| trusted | 64 | 3 | 2972.67 +/- 130.55 | 5512.69 +/- 240.13 | 80.963% +/- 0.001 |
| trusted | 64 | 6 | 2936.33 +/- 14.13 | 5579.76 +/- 26.86 | 72.584% +/- 0.000 |
| verified | 64 | 1 | 11953.33 +/- 377.04 | 1370.81 +/- 43.38 | 86.890% +/- 0.000 |
| verified | 64 | 3 | 12463.33 +/- 652.74 | 1314.96 +/- 68.20 | 80.684% +/- 0.001 |
| verified | 64 | 6 | 12281.67 +/- 70.63 | 1334.03 +/- 7.68 | 72.352% +/- 0.000 |

## Interpretation

Subset propagation reduces modeled wire traffic substantially while preserving
post-repair target payload completeness. In the 64-node, 3-target, even-latency
case, verified mode drops from roughly `2399.597 MB/epoch` under full
replication to `463.499 MB/epoch` with subset propagation and repair included.
Trusted mode drops from `2391.328 MB/epoch` to `455.230 MB/epoch`.

Trusted mode reaches payload-ready state faster because it models dispatch only.
Verified mode includes the echo, verification, proposal, and commit control
stages, so it has higher finality latency and lower payload-ready TPS for the
same data-plane workload. Both modes use the same subset payload propagation and
repair correctness condition.

The main protocol lesson is that recipient-filtered propagation must not equate
metadata convergence with data availability. The production observer should
continue to track both canonical metadata convergence and per-target payload
completeness, and reconciliation should treat missing target payloads as a
repairable availability gap rather than a successful epoch.

The first-round prefill optimization is specified separately in
[`prefill-dispatch.md`](prefill-dispatch.md). That proof defines deterministic
prefill dispatch placement: one prefill stage materializes the first data
frontier, then consensus starts one layer later.

## Reproducibility

Primary code and test harnesses:

- `src/subset_gossip.rs`
- `src/bin/blossom-subset-gossip-bench.rs`
- `benchmarks/scripts/run-subset-gossip-matrix.sh`
- `benchmarks/scripts/analyze-subset-gossip.py`

Validation commands run for this proof:

```text
cargo test --features availability-gossip
EPOCHS=50 REPEAT_RUNS=3 benchmarks/scripts/run-subset-gossip-matrix.sh
cmp -s benchmarks/results/subset_gossip_20260521_050337/subset_gossip_aggregate.csv \
       benchmarks/results/subset_gossip_20260521_051925/subset_gossip_aggregate.csv
```
