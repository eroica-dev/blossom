# Failure Boundary Algorithms

This note collects the exact edges where Blossom should stop, buffer, repair, or
fail closed. The goal is to make expected failure explicit: the protocol should
avoid losing correct data, but it must not pretend to make Byzantine-safe
progress when the evidence is below the safe boundary.

## Threshold Parameters

For a validator set of size `n`:

```text
f = floor((n - 1) / 3)
q = supermajority_count(n) = n - floor(n / 3)
l = max_liveness_omissions(n) = n - q
```

- `f` is the maximum Byzantine population the verified path claims to tolerate.
- `q` is the number of distinct current-validator votes needed for a
  supermajority certificate.
- `l` is the number of slow, missing, or crashed validators a stage can ignore
  for liveness. This is not the Byzantine safety bound.

For the default six-member quorum:

```text
n = 6
f = 1
q = 4
l = 2
```

The proof edge is:

```text
2q - n > f
```

Any two `q`-sized certificates intersect in more than `f` validators, so they
must share at least one honest signer when the actual Byzantine population is
`<= f`. At `q - 1`, that honest-overlap guarantee is intentionally not claimed.

## Algorithm: Admit Supermajority Evidence

```text
input:
  validators: current validator identities
  votes: signed votes
  target: epoch, nonce, round, stage, body/manifest hash

valid_voters = {}
for vote in votes:
  reject vote if signer not in validators
  reject vote if signature invalid
  reject vote if vote target != target
  add signer to valid_voters

if |valid_voters| >= q:
  accept certificate
else:
  fail closed or buffer; do not advance state
```

Expected failure edge:

- duplicate votes from one identity count once;
- out-of-membership votes count zero;
- stale or mismatched votes count zero;
- `q - 1` valid votes can be an assist hint, but not an advance certificate.

## Algorithm: Byzantine Population Gate

```text
input:
  n: validator count
  b: configured or observed Byzantine population for the verified simulation

if b > floor((n - 1) / 3):
  reject configuration or mark the run outside the verified safety claim
else:
  run verified/trustless path
```

Expected failure edge:

- When `b > f`, Blossom should not claim Byzantine safety.
- Trusted mode may model accidental faults, but it must not claim trustless
  Byzantine safety.

## Algorithm: Round-Skip Certificate Admission

```text
input:
  certificate
  manifest
  validators
  expected_last_epoch
  expected_nonce
  byzantine_fault_bound f

reject if certificate.to_round <= certificate.from_round
reject if certificate epoch/nonce != expected epoch/nonce
reject if certificate.manifest_hash != hash(manifest)
reject if certificate has fewer than q distinct valid current-validator votes
reject if manifest availability validation fails with min_replicas_per_block = f + 1

accept round-skip certificate
```

Expected failure edge:

- A valid skip certificate without a valid availability manifest is not enough
  to advance.
- In trustless production, each carried block needs at least `f + 1` eligible
  replica holders so at least one repair source remains honest if all Byzantine
  holders withhold data.

## Algorithm: Future-Round Assist

```text
input:
  current state
  future-round messages
  skip certificates
  local data status
  parent data status

if skip certificates do not cover every skipped round:
  BufferForCertificates

if local block is in candidate and first fanout did not complete:
  AssistDroppingLocalBlock

if local block is in candidate and first fanout completed but local block is not replicated:
  ServeDataBeforeAssist

if parent data is not replicated and not repairable:
  BufferForRepair

if local node holds unreplicated required parent data:
  ServeDataBeforeAssist

if future message is data-bearing and future body is not validated:
  RejectDataVoteUntilValidated

otherwise:
  Assist
```

Expected failure edge:

- Data loss is expected only for the pre-fanout private local block case.
- After first fanout, missing replication is repair work, not a drop decision.
- A node may assist with `q - 1` compatible future-round messages only if its
  own vote completes a valid certificate; it still advances only after the full
  certificate exists.

## Algorithm: Data-Loss Accounting

```text
valid_local_blocks =
  local blocks whose epoch and nonce match the canonical parent

intentionally_dropped_local_blocks =
  valid local blocks excluded by AssistDroppingLocalBlock before first fanout

incorrectly_lost_local_blocks =
  valid local blocks that were not intentionally dropped and have no active
  replica holder after dissemination, repair, pruning, and reconnect

if incorrectly_lost_local_blocks > 0:
  fail runtime reconciliation
```

Expected failure edge:

- `intentionally_dropped_local_blocks > 0` can be correct only when a first
  fanout skip excludes private data that never entered the dissemination tree.
- `incorrectly_lost_local_blocks > 0` is always a correctness failure.

## Algorithm: Repair And Reconciliation

```text
input:
  active validators
  canonical epoch hash
  canonical block manifest
  repair quorum
  repair fanout

reject trustless config if repair_quorum < q
reject trustless config if repair_quorum <= possible Byzantine responders

for lagging node:
  collect summaries from repair peers
  if a valid canonical summary quorum is available:
    fetch missing data and restate node
  else:
    collect block-level replica sources
    include the recipient's own local partial replica when valid
    if every canonical block is reconstructable:
      restate node and mark it full data holder
    else:
      keep pending reconciliation; do not advance to a descendant epoch
```

Expected failure edge:

- If enough valid repair sources do not exist, reconciliation must remain
  pending instead of fabricating convergence.
- If the network drops below the liveness threshold, the protocol may stall but
  should not violate safety.

## Algorithm: Subset Block Gossip Availability

```text
for each command in each block:
  commit canonical command metadata to the block hash
  keep full payload at the holder
  send full payload only to recipients in the command target set
  send tombstones/commitments to non-target recipients

after metadata convergence:
  for every command target:
    require the target to hold the full payload
    if missing, fetch from a full holder before marking data available
```

Expected failure edge:

- Metadata convergence is not sufficient for subset propagation correctness.
- Inline subset gossip can leave target payloads missing when the target only
  hears tombstone views.
- Correctness requires either a deterministic full-payload route to every
  target or an explicit pull-repair phase.

## Algorithm: Reconnect Admission

```text
input:
  dropped node identity
  active validators
  ping quorum
  approval quorum
  catch-up proof

reject trustless config if ping_quorum < q(active peers)
reject trustless config if approval_quorum < q(active peers)
reject if either quorum can be satisfied only by possible Byzantine voters
reject if reconnect identity/key does not match dropped identity
reject stale, replayed, or duplicate evidence
reject if catch-up proof cannot reconstruct canonical data
accept only after ping, catch-up, and admission vote thresholds pass
```

Expected failure edge:

- A dropped node cannot rejoin by only reaching a partition minority.
- Byzantine peers cannot admit stale state without catch-up proof.
- Duplicate votes do not increase the admission count.

## Algorithm: Partition And Churn Boundary

```text
while partition is active:
  accept valid local messages for unresolved epochs
  reject stale or mismatched evidence
  keep the lowest unresolved epoch pending
  do not form descendant epochs without a certified parent and repairable data

after partition heals:
  reconcile pending epoch first
  repair data availability
  then resume new epoch formation
```

Expected failure edge:

- If both sides cannot gather valid supermajority evidence, progress stalls.
- When partitions merge, conflicting branches must reconcile through the
  canonical certified parent before later epochs proceed.

## Current Coverage

Executable tests and models pin these boundaries:

- `trustless_byzantine_threshold_accepts_max_and_rejects_next`
- `trustless_repair_quorum_threshold_boundary_is_enforced`
- `trustless_reconnect_quorum_threshold_boundary_is_enforced`
- `trustless_reconnect_succeeds_at_exact_supermajority_threshold`
- `one_below_supermajority_loses_honest_overlap_guarantee`
- `incorrectly_lost_local_blocks_counts_expected_hashes_without_replicas`
- `skipped_first_fanout_drops_unshared_local_blocks_in_epoch_sim`
- `skipped_later_round_preserves_blocks_after_first_fanout`
- `deterministic_epoch_vulnerability_scenarios_run_sequentially`
- `byzantine_churn_under_threshold_preserves_epoch_progress`
- `healed_full_partition_reconciles_pending_epoch_before_resuming`
- `subset_gossip::tests::subset_gossip_converges_metadata_and_repairs_payloads`
- `subset_gossip::tests::sparse_inline_subset_can_need_repair`

Formal threshold models live in:

- `verification/creusot/thresholds/src/lib.rs`
- `verification/quint/blossom_thresholds.qnt`
- `verification/tla/BlossomThresholds.tla`
- `verification/verus/thresholds.rs`

Long-run empirical validation of these edges lives in
[`docs/proofs/failure-boundary-validation.tex`](failure-boundary-validation.tex).
The raw 2,000-epoch run data used for the current validation note was generated
under `benchmarks/results/proof_validation_20260521_022227`.

Recipient-filtered block propagation validation lives in
[`docs/proofs/subset-block-gossip.md`](subset-block-gossip.md).
