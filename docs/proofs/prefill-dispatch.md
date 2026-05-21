# Prefill Dispatch Proof

This note defines the prefill round as deterministic prefill dispatch. The
sender computes the future contacts for its local block from the public quorum
schedule and sends the needed payloads to those contacts before trustless
consensus begins.

The purpose is to replace the first data-spreading consensus round with one
non-consensus availability round while adding enough initial redundancy to avoid
orphaning correct local blocks at the root of the dissemination tree.

## Model

Let:

- `V` be the validator set, with `n = |V|`.
- `q` be the quorum size.
- `R = ceil(log_q(n))` be the number of consensus dissemination layers in the
  standard schedule.
- `B_i` be the local block created by validator `i`.
- `Q_r(v)` be the deterministic quorum containing validator `v` at consensus
  round `r`.
- `Hold_P(B_i, t)` be the set of validators that hold `B_i` at protocol time
  `t` in protocol `P`.

The standard trustless data path starts with:

```text
Hold_old(B_i, 0) = { i }
```

After old consensus round `0` completes, the block has reached a first
dissemination frontier:

```text
F_i = Hold_old(B_i, 1)
```

The prefill-dispatch path computes a deterministic contact set:

```text
C_i = prefill_dispatch_contacts(i, B_i, schedule)
```

The prefill stage replaces only old consensus round `0`. It does not replace
rounds `1..R-1`. The later consensus rounds still run, but their data dispatch
uses a precomputed inventory route: a sender pushes only the payloads the
recipient needs for its remaining dissemination subtree.

The strong version of the algorithm chooses `C_i` so that:

```text
F_i subset C_i
```

In the "send to future contacts" instantiation, `C_i` includes the first-round
frontier plus deterministic future branch contacts for `B_i`. A bandwidth-tuned
implementation may choose a smaller holder map, but then it must prove the same
condition per active branch:

```text
for every future branch A:
  |C_i intersect A intersect Correct| >= 1
```

For Byzantine-safe availability with a local branch fault bound `f_A`, the
stronger sufficient condition is:

```text
for every future branch A:
  |C_i intersect A| >= f_A + 1
```

The simulator default for `q = 6` and one Byzantine route withholder uses:

```text
|C_i| ~= (q * R) - 1
```

For `n ~= 1000`, `R = ceil(log_6(1000)) = 4`, so this gives `23` prefill
recipients per local block.

## Algorithm

For each epoch and local block `B_i`:

```text
1. All validators derive the same quorum schedule from the epoch seed.
2. Owner i computes C_i, the future contacts for B_i.
3. Owner i sends the needed payloads for B_i to every validator in C_i in one
   prefill stage.
4. Each recipient validates the sender identity, block hash, commitments,
   epoch, and nonce before recording itself as a holder.
5. Consensus starts at round 1, not round 0.
6. During every later consensus round, each sender advertises or derives its
   inventory and pushes novel payloads needed by the recipient's remaining
   subtree.
```

The prefill stage does not finalize anything. It only places data. The remaining
trustless consensus stages still validate and certify the canonical epoch state.

## Trustless Push Availability

In a trustless deployment, quorum-time availability cannot depend on pull repair
from a known holder. That assumption is too strong: a Byzantine holder can
acknowledge the schedule, appear in the holder map, and then withhold data until
the quorum is blocked.

The trustless proof therefore uses a push invariant. For each block `B_i` and
future branch `A`, the prefill stage must push `B_i` to enough validators in
`A` before the branch can need the block:

```text
Push_i(A) = C_i intersect A
```

Trustless branch availability requires:

```text
|Push_i(A)| >= f_A + 1
```

where `f_A` is the maximum number of Byzantine or unavailable pushed holders in
branch `A`. This gives at least one correct pushed holder in every branch:

```text
|Push_i(A) intersect Correct| >= 1
```

The branch can then continue because the required data has already been pushed
into the branch. If this invariant is not satisfied, the branch is unavailable
for trustless consensus and must not justify skipping round `0`. Pull, repair,
and reconciliation are outside this trustless prefill proof.

## Lemma 1: Common Future-Contact Map

All honest validators compute the same `C_i` for every owner `i`.

Proof. `C_i` is a deterministic function of public inputs: the validator set,
the epoch seed, the quorum size, and the consensus schedule. Honest validators
with the same epoch view therefore derive the same contact set. A Byzantine node
may omit sends or send invalid data, but it cannot make honest validators accept
a different expected contact map without changing the public schedule inputs.

## Lemma 2: Prefill Dominates The Skipped First Round

At the start of consensus round `1`, the prefill protocol has at least the data
availability that the old protocol would have had after completing consensus
round `0`.

Proof. By construction, the strong prefill contact set satisfies:

```text
F_i subset C_i
```

After the prefill stage:

```text
Hold_prefill(B_i, start_round_1) = { i } union Delivered(C_i)
```

For all correct recipients in `C_i`, authenticated delivery and block validation
insert `B_i` into the local holder set. Under eventual delivery to correct
contacts:

```text
F_i intersect Correct subset Hold_prefill(B_i, start_round_1)
```

Thus the correct portion of the old post-round-0 holder frontier is already
present before the first active consensus round begins.

## Lemma 3: Later Dissemination Is Monotone In Holders

If one execution begins a round with a holder set that is a superset of another
execution's holder set, then after the same honest dissemination step it still
has a holder set that is a superset.

Proof. A correct node only adds validated block data; it does not remove a
valid block from its holder set during dissemination. The transition for one
round is:

```text
Hold_next = Hold_current union DeliveredFrom(Hold_current)
```

Set union is monotone. Therefore a larger initial holder set cannot produce a
smaller later holder set under the same delivery assumptions.

## Theorem 1: One Fewer Consensus Round

If the prefill-dispatch contact set satisfies `F_i subset C_i` for every correct
owner `i`, then the prefill protocol can skip consensus round `0` and execute:

```text
1 prefill stage + max(R - 1, 1) consensus rounds
```

instead of:

```text
R consensus rounds
```

while preserving the old protocol's data availability for all later rounds.

Proof. Lemma 2 shows that the prefill protocol starts consensus round `1` with
at least the correct holder frontier that the old protocol would have had after
round `0`. Lemma 3 applies inductively to rounds `1..R-1`: every later round in
the prefill execution starts with a holder set that is a superset of the
corresponding old execution. Therefore no later consensus round depends on data
availability that was lost by skipping round `0`.

The final consensus state remains trustless because prefill does not certify a
block. It only provides pushed availability holders. Consensus safety still
comes from the remaining signed verification, proposal, and commit thresholds.

## Theorem 2: Correct Local Blocks Are Not Orphaned By The Skip

A correct local block `B_i` is not orphaned solely because consensus round `0`
was skipped, provided every future branch that may need `B_i` contains at least
one correct prefill holder for `B_i`.

Proof. A block is orphaned by the first-round skip only if it remains known
solely to its owner while the rest of the dissemination tree advances without a
pushed branch holder. Future-contact prefill sends `B_i` to the future contacts
before the tree advances. For each future branch `A`, the assumption gives:

```text
C_i intersect A intersect Correct != empty
```

So each branch has at least one correct pushed holder for `B_i` before it can
require that data. Therefore the skip does not create an orphaned correct block.

## Redundancy Bound

Let:

```text
h_i(A) = |C_i intersect A|
b_i(A) = number of Byzantine or unavailable holders in C_i intersect A
```

The branch has a live pushed holder when:

```text
h_i(A) - b_i(A) >= 1
```

A sufficient static rule is:

```text
h_i(A) >= f_A + 1
```

where `f_A` is the maximum Byzantine or unavailable holder count allowed for
branch `A`.

The maximum-redundancy version sets `h_i(A)` to the number of future contacts
in that branch. If the branch is a quorum of size `q`, and all quorum members
are contacts, then the branch can lose up to `q - 1` prefilled holders before
data availability for that block is lost. The implemented default is more
bandwidth-conscious: it uses a small deterministic prefill contact set and then
relies on subtree payload routing in the remaining consensus rounds.

## Optimization Math

Let:

```text
R     = ceil(log_q(n))
sigma = modeled dispatch-stage latency for one consensus layer
delta = modeled prefill edge latency
rho   = extra future contact per live branch per later consensus layer
d     = per-block prefill fanout
```

The implemented prefill-dispatch fanout is:

```text
d(rho) = (q - 1) + rho * q * (R - 1)
```

The default BFT route-withholding setting uses `rho = 1`:

```text
d = (q * R) - 1
```

For `q = 6`:

```text
n = 36 or 72: R = 2 or 3, d = 11 or 17
n ~= 1000:    R = 4,       d = 23
```

This is the important change from the older branch-holder experiment. The
prefill no longer scales as `O(n / q)` per block. It scales as `O(q log_q n)`
per block, while the remaining `R - 1` consensus rounds still run.

The later consensus rounds use subtree payload routing. For a sender `s`,
recipient `r`, block owner `i`, and consensus round `j`, the pushed payload set
is:

```text
Need(i, r, j) =
  commands in B_i whose target set intersects Reach(r, j + 1)
```

where `Reach(r, j + 1)` is the set of final recipients that can be reached from
`r` after it receives data in round `j`. This is why prefill can stay small
without falling back to full-block forwarding.

### Latency

In verified mode, the current model charges one data dispatch stage and four
control stages per consensus round:

```text
old_verified_latency = R * 5 * sigma
prefill_verified_latency = delta + (R - 1) * 5 * sigma
saved_verified_latency = 5 * sigma - delta
```

In trusted mode, consensus control is absent:

```text
old_trusted_latency = R * sigma
prefill_trusted_latency = delta + (R - 1) * sigma
saved_trusted_latency = sigma - delta
```

For the even-latency simulator runs with `q = 6`, the per-edge latency is
`150 ms`, and the simulator sums one dispatch-stage latency per active branch:

```text
sigma = m * 150 ms
delta = 150 ms
```

That means verified mode saves one consensus layer's dispatch and control cost,
minus the single prefill hop:

| `n` | `R` | old verified | prefill verified | latency reduction |
|---:|---:|---:|---:|---:|
| 36 | 2 | 9000 ms | 4650 ms | 48.3% |
| 72 | 3 | 27000 ms | 18150 ms | 32.8% |
| 1296 | 4 | 648000 ms | 486150 ms | 25.0% |

The 1296-node row uses the simulator's full quorum-stage accounting: `R = 4`,
`prefill_skip_rounds = 1`, and `rounds = 3`.

### Wire Break-Even

Let:

```text
W_old     = standard subset wire bytes after repair
W_tail(k) = post-prefill routed payload bytes + remaining control bytes
P(k)      = prefill bytes
W_new(k)  = P(k) + W_tail(k)
```

Prefill wins on wire when:

```text
P(k) < W_old - W_tail(k)
```

Because `P(k)` is approximately linear in the per-block fanout `d(k)`, this
gives a concrete maximum safe fanout:

```text
d_max ~= (W_old - W_tail) / prefill_cost_per_fanout
```

Current simulator checks for `q = 6` show:

| Scenario | `n` | commands/node | fanout | rounds | total wire/epoch | payload complete before repair |
|---|---:|---:|---:|---:|---:|---|
| standard subset + repair | 72 | 16 | 0 | 3 | 64.3 MB | no |
| prefill dispatch | 72 | 16 | 17 | 2 | 11.5 MB | yes |
| standard subset + repair | 1000 | 1 | 0 | 4 | 1797.4 MB | no |
| prefill dispatch | 1000 | 1 | 23 | 3 | 182.2 MB | yes |

This gives the main optimization conclusion:

- one prefill stage reliably removes one consensus layer from the latency path;
- prefill dispatch plus subtree payload routing can reduce total wire and
  complete without a repair phase;
- full-block forwarding is correct but expensive, so later rounds should route
  only payloads needed by the recipient's remaining subtree;
- for trustless deployments, the useful target is enough pushed redundancy for
  the route-withholding bound, not all-contact replication.

### Byzantine Withholding Check

The trustless path must assume that a holder may acknowledge the schedule but
withhold data later. The executable model now treats the first `f_A` pushed
holders for each branch payload as Byzantine withholders. A branch is complete
only if at least one additional pushed holder already has the data. Let `k` be
the number of pushed holders for that branch payload:

```text
k > f_A
```

For `q = 6`, the simulator uses `f_A = 1`. The older branch-holder boundary
and the prefill-dispatch route-withholding check behave as expected:

| Scenario | `k` | Byzantine withholders per branch | Expected result |
|---|---:|---:|---|
| unsafe prefill | 1 | 1 | missing payloads remain |
| BFT prefill | 2 | 1 | payloads complete before repair |
| prefill dispatch | route redundancy enabled | 1 | payloads complete before repair |

This is deliberately stronger than a happy-path redundancy check. It verifies
that the pushed holder set contains enough validated recipients before the
branch needs the data.

## Safety Boundaries

The proof does not hold if any of these are false:

- honest nodes do not agree on the prefill-dispatch schedule;
- prefill messages are not authenticated by owner identity, epoch, and nonce;
- recipients accept blocks whose hashes or payload commitments do not validate;
- every prefilled holder for a block in a future branch is Byzantine or
  unavailable;
- the implementation treats an unvalidated peer as a pushed holder;
- the pushed holder set has no correct recipient after Byzantine withholders are
  removed;
- a prefill contact set is tuned below the `f_A + 1` branch threshold in a
  trustless deployment.

These are explicit failure boundaries, not hidden assumptions. A production
implementation should expose them as validation checks, observer metrics, and
simulation scenarios.

## Code Mapping

The simulator exposes `SubsetPrefillMode::PrefillDispatch`. The CLI value is
`prefill-dispatch`.

Relevant simulator hooks:

- `consensus_start_round` caps the prefill replacement to one skipped consensus
  layer.
- `build_prefill_plan` computes the initial holder map.
- `prefill_dispatch_fanout` sets the default fanout to `qR - 1`.
- `apply_prefill` sends the local block's needed subtree payloads to the
  planned holders in one modeled network stage.
- `build_future_reachability` computes each recipient's remaining subtree.
- `precomputed_inventory_routes_for_quorum` models later scheduled pushes from
  validated holders instead of spraying duplicate blocks.

## Tested Obligations

The current branch exercises the proof obligations with:

- `prefill_dispatch_replaces_first_consensus_round`;
- `prefill_dispatch_fanout_scales_with_log_rounds`;
- `prefill_dispatch_routes_subtree_payloads_without_repair`;
- `prefill_dispatch_survives_one_byzantine_route_withholder`;
- `prefill_dispatch_start_is_always_one_round`;
- `prefill_dispatch_rejects_multi_round_skip_override`;
- `precomputed_inventory_routes_pick_one_holder_for_missing_payloads`;
- `single_prefill_holder_is_not_byzantine_resilient`;
- `bft_prefill_survives_one_byzantine_withholder_per_branch`;
- full `cargo test --features availability-gossip`;
- large smoke simulations such as `n=1296, q=6`, which verify one prefill stage
  plus `R - 1` active consensus rounds.
