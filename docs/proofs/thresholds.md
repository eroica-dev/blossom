# Correct And Faulty Thresholds

This note states the threshold assumptions used by the verified, trustless
path of the simulator and by the protocol stages that require supermajority
evidence.

## Definitions

- `n` is the number of validators eligible to vote on a stage proof.
- `f = byzantine_fault_bound(n) = floor((n - 1) / 3)` is the maximum
  Byzantine population tolerated by the verified path.
- `q = supermajority_count(n) = n - floor(n / 3)` is the minimum number of
  distinct current-validator votes required for a supermajority proof.
- `l = max_liveness_omissions(n) = n - q` is the number of slow or absent
  validators a stage can ignore for progress. This is not a Byzantine safety
  bound.

Correct evidence is evidence signed by distinct validators for the current
epoch, stage, nonce, identity, and body being admitted. Faulty evidence includes
stale, replayed, forged, duplicate, Sybil, out-of-epoch, or out-of-membership
evidence.

In code, `distinct_current_validator_count` performs the current-validator
deduplication step, and `has_distinct_supermajority` applies the threshold to
that deduplicated evidence set.

## Safety Threshold

The safety condition is `b <= f`, where `b` is the actual Byzantine population.
The trustless simulator rejects configurations with `b > f`. Trusted mode is a
separate operational model and must not be used to claim Byzantine safety.

Any two vote sets of size `q` intersect in at least `2q - n` validators. Split
by `n mod 3`:

- If `n = 3k`, then `q = 2k`, `f = k - 1`, and the intersection is at least
  `k`, which is greater than `f`.
- If `n = 3k + 1`, then `q = 2k + 1`, `f = k`, and the intersection is at
  least `k + 1`, which is greater than `f`.
- If `n = 3k + 2`, then `q = 2k + 2`, `f = k`, and the intersection is at
  least `k + 2`, which is greater than `f`.

So, under `b <= f`, two accepted supermajority proofs must share at least one
honest validator. An honest validator signs only one valid interpretation for a
stage body, so conflicting accepted proofs cannot both be valid.

## Fault Boundary

If the quorum is lowered to `q - 1`, the minimum intersection becomes small
enough to be covered entirely by the Byzantine set for the same `f` bound. At
that point two conflicting proofs can be assembled without a guaranteed honest
overlap. The implementation treats this as an unsafe configuration in verified
mode.

The executable tests pin both sides of the boundary:

- `six_node_quorum_distinguishes_liveness_from_byzantine_safety` proves that a
  six-member quorum can ignore two slow nodes for liveness while tolerating one
  Byzantine signer for honest-overlap safety.
- `supermajority_count_rejects_under_threshold_and_overfull_votes` rejects
  duplicate/Sybil-style over-counts as invalid proof counts.
- `distinct_current_validator_supermajority_ignores_duplicates_and_outsiders`
  proves duplicate votes and out-of-membership votes do not inflate evidence.
- `distinct_current_validator_supermajority_rejects_duplicate_shortfall` proves
  duplicate evidence cannot turn three distinct voters into a six-node
  supermajority.
- `supermajority_intersection_exceeds_bft_fault_bound` proves `q` has honest
  overlap for `n = 1..256`.
- `one_below_supermajority_loses_honest_overlap_guarantee` proves `q - 1`
  loses that guarantee.
- `trustless_byzantine_threshold_accepts_max_and_rejects_next` accepts `f`
  Byzantine nodes and rejects `f + 1`.
- `trustless_repair_quorum_threshold_boundary_is_enforced` accepts repair
  quorum `q` and rejects `q - 1`.
- `trustless_reconnect_quorum_threshold_boundary_is_enforced` accepts
  reconnect ping/admission quorum `q` and rejects `q - 1`.
- `trustless_reconnect_succeeds_at_exact_supermajority_threshold` verifies a
  dropped node can still reconnect when the exact safe threshold is available.

## Stage Application

Membership pruning, repair, reconnect catch-up proofs, reconnect ping evidence,
and reconnect admission votes use the same rule: count only distinct current
validator identities, bind evidence to the current epoch/stage/body, and require
the verified-path quorum. Duplicate votes, stale proofs, replayed evidence, and
identity changes may be measured as telemetry, but they must not increase the
proof count.
