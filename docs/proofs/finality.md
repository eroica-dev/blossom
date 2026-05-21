# Runtime Finality Gate

This note captures the current Stage 9 runtime finality gate. The lower-level
`LocalState::advance_epoch` transition already existed; this gate connects it
to deployable runtime commit intake.

## State Transition

When `NodeRuntime` accepts a true commit:

1. The commit must pass message-signature and round-membership checks.
2. The runtime must already have a true proposal supermajority for the quorum.
3. The commit sender is inserted into the latest true-commit sender set.
4. If the true-commit sender set reaches the quorum supermajority threshold,
   the runtime calls `LocalState::advance_epoch(last_epoch, nonce, round, true)`.

`LocalState::advance_epoch` checks that the proposed last epoch and nonce match
the current chain tip and expected next nonce. If there are additional rounds
for the current consensus, it advances the round. If the final round has
completed, it creates one new epoch whose block set is the quorum's verified
block set.

## Safety Sketch

Finality is downstream of the previous gates:

- Dispatch intake verifies blocks before adding them to `verified_blocks`.
- Verification votes can only reference that local verified set.
- True proposals require a distinct verification supermajority over that same
  set.
- True commits require a local true proposal supermajority and then a distinct
  true commit supermajority.

Consensus-message intake checks the chain tip and nonce before stage
accounting, so stale commit messages cannot append a descendant to the wrong
parent or update old quorum state. Once the epoch has advanced, replayed
messages for the old parent are rejected as stale before commit accounting.

## Progress Sketch

If honest quorum members verify the same block set, deliver a true proposal
supermajority, and then deliver a true commit supermajority, the last commit
that crosses the threshold triggers epoch advancement locally. For a one-round
quorum this produces the next epoch immediately. For multi-round schedules it
moves to the next round until the final round completes.

## Current Tests

- `cargo test -q advance_epoch`
- `cargo test -q receive_commit_supermajority_advances_epoch`
- `cargo test -q receive_commit`
