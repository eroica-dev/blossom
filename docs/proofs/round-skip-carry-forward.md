# Round-Skip Carry-Forward Proof Sketch

This proof sketch covers the bounded-await future-round assist rule implemented
in `src/round_skip.rs` and exercised by `blossom-sim`.

## Objects

- A **data dissemination manifest** commits an epoch, nonce, first fanout round,
  last certified round, certified block-set hash, carried block hashes, dropped
  local block hashes, source identities, and per-block replica holders.
- A **round-skip vote** is signed by one current validator over the epoch,
  nonce, source round, target round, and manifest hash.
- A **round-skip certificate** is accepted only when distinct current validators
  with valid signatures reach the implemented supermajority threshold
  `S(n) = n - floor(n / 3)`.

## Safety

Replay and stale evidence cannot move state because certificate validation is
parameterized by the expected last epoch and nonce. Evidence from any other
epoch or nonce is rejected before threshold counting.

Duplicate votes cannot inflate evidence because only distinct current
validator keys are counted. Out-of-membership votes cannot help because the
valid-voter set is intersected with the current validator set before applying
`S(n)`.

Identity substitution cannot help because each vote is verified against the
public key it claims as voter. A Sybil key outside the current validator set
may produce a valid signature for itself, but it does not increase the
certificate count.

Malformed or mismatched votes cannot help because a valid vote must match the
certificate's epoch, nonce, source round, target round, and manifest hash.
Changing any signed field invalidates the signature or removes the vote from
the matching set.

Skipping the first fanout round is special. If the local block has not reached
the first dissemination target, the assist decision is
`AssistDroppingLocalBlock`; that block is excluded from the assisted branch.
This avoids certifying a future branch that depends on private data that never
entered the dissemination tree.

Skipping after first fanout is different. Once the first fanout is certified,
the block has entered the replicated data tree and can be carried by manifest
through future-round assist. Missing copies are repair/reconciliation work, not
a reason to drop the block by default.

If the first fanout completed but the local block does not yet have sufficient
replica evidence, an honest node serves or repairs the block before assisting
instead of dropping it. This makes data loss the final safe fallback, reserved
for the pre-fanout case where the data never left the root subset.

Carried-forward data is not considered available merely because some node has
the future epoch hash. For every carried block, the manifest must identify at
least one replica holder. A node can become a full data holder only after it can
reconstruct every carried block from the replica sets. This allows repair to
combine pieces from multiple peers; it does not require a single peer to already
hold the entire canonical block set after the first fanout.

The simulator checks this as a no-incorrect-loss invariant. For each epoch it
counts valid local blocks, valid local blocks intentionally dropped by the
first-fanout skip rule, and valid local blocks incorrectly lost. A non-dropped
valid block is preserved if its hash remains reconstructable from at least one
active replica holder, even when no single node yet has the whole canonical
block set. Correctness still requires repair/reconciliation to finish by making
every active correct node a full data holder.

For production trustless admission, the manifest availability check should use
`f + 1` replica holders per carried block, where `f` is the configured Byzantine
fault bound. That threshold guarantees at least one honest repair source per
carried block when at most `f` validators are Byzantine. Trusted deployments can
use a lower threshold only under the explicit assumption that listed holders do
not intentionally withhold valid data.

Data-bearing future-round votes are rejected until the body and parent data
chain are validated. A node holding unreplicated certified parent data must
serve or gossip that data before, or together with, its assist.

## Progress

Under partial synchrony, a node may buffer unsupported future-round messages
while it fetches missing skip certificates or parent data. If the node obtains
enough compatible certificates and the carried-forward data is either already
replicated or repairable, it may assist the future round. If the data is not
repairable, the node waits for repair instead of voting for a branch it cannot
justify.

Slow lower-round nodes are not automatically classified as Byzantine. A
future-round certificate is evidence that the network can advance; it is not,
by itself, evidence that lagging validators equivocated or should be removed.
Membership removal remains a separate threshold decision.

## Tested Boundaries

Executable tests cover:

- first fanout skipped means unshared local blocks are dropped;
- later skip means certified local blocks are carried forward;
- later skip with missing local replica evidence serves/repairs data before
  assisting rather than dropping;
- missing skip certificates buffer instead of advancing;
- carried blocks require replica evidence;
- manifest validation can require Byzantine-safe `f + 1` replica holders per
  carried block;
- repair can reconstruct from distributed replicas without a pre-existing full
  data holder;
- runtime reconciliation counts partial local replicas as reconstruction
  sources, so the common "each node still has its own block" case is repairable;
- simulator reports distinguish intentionally dropped first-fanout local blocks
  from incorrectly lost valid blocks;
- duplicate votes do not reach supermajority;
- out-of-membership votes do not count;
- stale certificates are rejected;
- mismatched or tampered votes do not count;
- simulator runs expose skipped-message, assist, dropped-block, and
  carried-forward counters.
