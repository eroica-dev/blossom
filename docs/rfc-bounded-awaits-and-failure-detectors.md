# RFC: Bounded Awaits And Failure Detectors

Status: draft

## Summary

Blossom should remain patient at the consensus layer but bounded at the I/O
layer. Removing the simulator's round timeout avoids incorrectly discarding
valid high-latency consensus messages, but no runtime task should await one
peer forever. A silent peer is modeled as omission/Byzantine behavior; it can
lose its contribution to a quorum, but it cannot block all honest progress.

Core rule:

```text
Safety never depends on time.
Liveness and resource protection require bounded local waits.
Progress waits for quorum, not for all peers.
```

## Motivation

Today the transport path has awaits that can remain pending if a peer accepts a
connection and then goes silent. This creates a liveness and resource-risk even
when the protocol model allows high latency. We need to separate two concepts:

- **Consensus patience:** late but valid messages should be accepted while they
  still target the current epoch, nonce, round, stage, and body.
- **Operation deadlines:** connect/read/write/broadcast operations must return
  within local resource bounds.

## Non-Goals

- Do not reintroduce a fixed consensus round cutoff as a safety rule.
- Do not convict or drop nodes from one local timeout.
- Do not require all peers to respond before a stage can progress.
- Do not make trusted mode claim Byzantine liveness.

## Terms

- **Deadline:** a local resource bound for an I/O operation.
- **Timeout observation:** local evidence that one operation did not complete
  before its deadline.
- **Suspect peer:** a peer with recent timeout/error observations.
- **Faulty peer:** a peer removed or demoted by the membership protocol after
  threshold evidence.
- **Late message:** a valid message that arrives after a local operation
  deadline or after another path already made progress.
- **Assist threshold:** enough compatible future-round evidence that the local
  node can complete a certificate by adding its own valid vote.
- **Advance threshold:** enough compatible future-round evidence to form a
  certificate without assuming any additional future vote.

## Proposed Design

### 1. Add Bounded Transport Operations

Add configurable deadlines around TCP operations:

- connect deadline
- write deadline
- read-response deadline
- server idle-connection deadline

Initial defaults should be conservative and overrideable:

```text
BLOSSOM_TCP_CONNECT_TIMEOUT_MS = 2000
BLOSSOM_TCP_WRITE_TIMEOUT_MS = 5000
BLOSSOM_TCP_READ_TIMEOUT_MS = 10000
BLOSSOM_TCP_IDLE_TIMEOUT_MS = 30000
```

Timeouts return ordinary transport errors. They do not mutate consensus state
directly.

### 2. Broadcast Returns Partial Receipts

Broadcast should not wait for every spawned peer task. It should support a
policy like:

```rust
struct BroadcastPolicy {
    min_successes: Option<usize>,
    max_wait_ms: u64,
}
```

Behavior:

- return once `min_successes` accepted receipts arrive, when configured;
- otherwise return when all peers responded or `max_wait_ms` expires;
- record missing peers as timeout receipts;
- abort or detach still-pending peer tasks after the policy completes.

Consensus stages should pass the relevant supermajority threshold when they
know it. Best-effort gossip can use `min_successes = None`.

### 3. Add Local Failure Detector State

Timeouts feed a local, non-authoritative failure detector:

```text
Healthy -> Suspect -> Recovering
Healthy -> Suspect -> DropCandidate
DropCandidate -> Dropped only by membership consensus
Recovering -> Healthy after successful responses
```

The detector tracks:

- consecutive timeouts;
- recent successful responses;
- last successful epoch/nonce observed;
- error kind counts;
- peer score or suspicion level.

This state is advisory. It can affect fanout order, retry targets, telemetry,
and repair priority. It cannot by itself remove a validator from consensus.

### 4. Quorum-First Stage Progress

Every stage should define its completion condition as:

```text
enough valid evidence for the stage body
```

not:

```text
every peer responded
```

For trustless mode, "enough" means distinct current-validator supermajority
evidence bound to the current epoch, nonce, round, stage, identity, and body.

If a stage cannot gather quorum evidence, it enters recovery:

- request missing blocks/proofs from alternate peers;
- reconcile the lowest unresolved epoch;
- retry under the same parent/nonce until a certified result exists;
- only then advance to the next nonce.

### 5. Future-Round Buffering And Round Jump

Nodes may collect valid messages for the current round and for future rounds.
Future-round messages are not immediately applied to the current round state,
but they are validated and buffered by:

```text
(group_id, parent_epoch_hash, nonce, round, stage, body_hash)
```

A node should advance to a future round when it observes a valid
**advance certificate** for that future round. The certificate threshold is the
normal distinct current-validator supermajority for the relevant round
membership:

```text
advance_threshold = supermajority_count(round_members.len())
assist_threshold = advance_threshold - 1
```

In this RFC's notation, if `q` already means the required supermajority count,
then the advance threshold is `q`, not `2q/3 - 1`. If `q` means the committee
size, then the threshold is `supermajority_count(q)`. A `2q/3 - 1` rule is below
the honest-overlap boundary for the committee sizes Blossom uses unless it is
being used only as an assist threshold that is completed by the local node's own
valid vote. For the default six-member quorum, `advance_threshold = 4` and
`assist_threshold = 3`.

The advance certificate must contain either:

- a quorum certificate for a concrete future-round stage body; or
- a timeout/skip certificate proving a supermajority of current round members
  abandoned the lower round without committing a conflicting body.

Raw future-round messages without an embedded certificate are only hints. They
can trigger fetch/repair/pacemaker work, but they must not force a state
transition.

There are two separate future-round actions:

- **Assist:** if a node receives `assist_threshold` distinct, valid, compatible
  future-round messages from other current validators, and the node has not
  already voted for a conflicting body in that round/stage, it should add its
  own vote and broadcast it. This lets a six-member quorum make progress when
  three peers have already reached the future round and the local node can be
  the fourth.
- **Advance:** the node applies the future-round state only after it has a full
  advance certificate. The certificate may include the node's own newly emitted
  vote, but the local state transition is justified by the completed
  supermajority, not by the partial hint alone.

Assist must be stage-aware:

- For a timeout/skip or round-change assist, the local vote carries the node's
  last certified state, lock, and checkpoint reference. It does not claim to
  have validated a new future-round data body.
- For a data-bearing future-round body, the local node can assist only after it
  has fetched and validated the body, data-availability evidence, and parent
  certificate chain. A hash-only hint can trigger fetch/repair, but it cannot
  receive the local node's data vote.

After assisting, the node is locked out of new conflicting votes for the lower
round, but it is not blocked from serving data it already knows. It should keep
answering repair, catch-up, and proof requests for previous certified rounds and
for any lower-round data it already accepted. This lets slower honest peers
catch up without treating the assisting node as unavailable or Byzantine.

Example: if round 1 is certified, round 2 is hanging, and the node receives
enough valid round-3 messages to assist, the node may emit a round-3
round-change/skip assist that references its round-1 certified state and the
certificate chain proving round 2 was safely skipped. It must not claim or vote
for a round-2 data body it has not validated. If the round-3 messages do not
carry enough evidence to justify skipping round 2, the node buffers them and
fetches the missing certificates instead of assisting.

Future-round assist must also preserve Blossom's all-data dissemination
invariant. Skipping a stalled round skips that round's uncertified consensus
result; it must not skip, orphan, or under-replicate data from the last
certified branch. The protocol's intentional duplication means every honest
active node should eventually receive all certified data, even if some nodes are
temporarily slow and need repair.

A node can assist round 3 from a round-1 certified state only when round 1's
certified data is either already disseminated according to the protocol's
replication target or is carried forward through a repairable availability
manifest. If the node holds data that is required by the certified branch but
has not yet reached the replication target, it must serve or gossip that data
before, or together with, its round-change assist.

The availability manifest tracks replicas per carried block. A later repair
round may reconstruct the full canonical data set from multiple replica
holders; it does not require any one peer to already hold every block
immediately after first fanout. The no-loss invariant is per-block: every
carried block must have at least one active repair source, and a node is not
fully caught up until it has reconstructed every carried block.

This distinction is now explicit in the simulator accounting:
`valid_local_blocks` counts well-formed local contributions for the epoch,
`intentionally_dropped_local_blocks` counts valid contributions excluded only by
the first-fanout skip rule, and `incorrectly_lost_local_blocks` counts valid
non-dropped contributions that lost all active replica sources. Reconciliation
is allowed to assemble the full data set from partial replicas, including the
recipient's own local block, before marking that node as a full data holder.

The round-skip decision is tuned to minimize correct-data loss: after first
fanout, insufficient replica evidence returns `ServeDataBeforeAssist`, not
`AssistDroppingLocalBlock`. In trustless production, the certificate should be
validated against the concrete manifest with a per-block threshold of `f + 1`
replica holders, where `f` is the configured Byzantine bound. This keeps the
branch repairable even if all Byzantine holders withhold data.

An assist vote must therefore carry or reference:

- the last certified state root and certificate;
- the data-dissemination certificate, manifest, or checkpoint for that state;
- any locally held certified data shards or blocks that have not yet reached the
  required replication target; and
- the timeout/skip evidence for every skipped round.

If those availability obligations cannot be met, the node may request repair and
buffer the future-round messages, but it must not help certify a descendant
round that would make the certified branch unrecoverable.

The progress gate should still avoid waiting for literally every peer before
every round transition, because a single crashed node would stall the network.
Instead, the certificate proves the certified branch is durably replicated, and
repair/anti-entropy continues until every non-faulty active node has the full
data set. Observer telemetry should track this as replication lag: which nodes
are missing which certified block manifests, how long they remain behind, and
whether catch-up completed before later finality.

The first fanout round is special because it is where a node's personal block
first leaves the root subset of the dissemination tree. If that first fanout is
skipped before the local block reaches the replication target, the local block
must be dropped from the assisted future branch. The node may still assist a
round change from the previous certified checkpoint, but it must not smuggle its
unshared local block into a later round where only a descendant subset can see
it. This keeps distribution and correctness aligned: either the block entered
the certified dissemination tree, or it is excluded from the future branch.

For arbitrary future rounds, messages must carry or reference the certificate
chain that justifies reaching that round. A node may buffer messages for any
future round, but it should fetch missing certificates before assisting or
advancing. This prevents a malicious peer from causing unbounded round jumps by
advertising unsupported high round numbers.

When a node advances by certificate:

- it records the certificate that justified the jump;
- it keeps lower-round messages for reconciliation/equivocation evidence;
- it rejects lower-round messages as stale only after they conflict with a
  certified higher-round state;
- it may jump over more than one round if the certificate chain justifies the
  highest observed round.

This gives the protocol a way to avoid waiting on crashed lower-round peers
without making local timeouts part of safety.

Slow lower-round nodes are not Byzantine by default. A node that observes a
future-round certificate should classify missing or lower-round peers as
lagging/recoverable unless there is cryptographic evidence of misbehavior, such
as equivocation, invalid signatures, identity misuse, or threshold membership
evidence. Higher-round progress can trigger catch-up and repair, but it cannot
by itself justify dropping a slower honest validator.

### 6. Late Message Handling

Late messages are not automatically bad. On arrival:

- accept if the message is still current and valid;
- use for repair/reconciliation if it targets an unresolved epoch;
- reject as stale if the local node has already finalized a different epoch or
  moved beyond the target nonce with a valid certificate;
- never count duplicates or out-of-membership evidence.

### 7. Drop And Reconnect Remain Consensus Decisions

A peer may be locally suspected from timeouts, but dropping a validator from the
active set requires the existing membership-removal path and threshold evidence.

Reconnect requires:

- same identity/key;
- ping evidence from enough active peers;
- catch-up proof or checkpoint validation;
- admission approval quorum.

Timeouts can trigger the reconnect path, but they cannot bypass it.

## Implementation Sketch

Implemented now:

- shared protocol helpers in `src/round_skip.rs` for future-round assist
  decisions, first-fanout data manifests, signed round-skip votes, and
  distinct-current-validator round-skip certificates;
- simulator reuse of the same assist decision model, so skipped-round tests and
  long-run metrics exercise the protocol helper rather than a duplicate model;
- simulator no-loss accounting for valid, intentionally dropped, and
  incorrectly lost local blocks, with runtime reconciliation failing on any
  incorrectly lost block;
- manifest availability validation and certificate-manifest validation with a
  configurable per-block replica threshold;
- proof sketch in `docs/proofs/round-skip-carry-forward.md`.

Remaining runtime work:

1. Add timeout helpers in the TCP/wire layer.
2. Wrap `TcpConnection::connect`, request writes, and response reads.
3. Add server idle deadline around `read_wire_request_frame_optional`.
4. Extend `BroadcastReport` with timeout/missing receipts.
5. Add `BroadcastPolicy` and update broadcast call sites.
6. Add local peer health state and telemetry events:
   `peer_timeout`, `peer_suspect`, `peer_recovered`, `broadcast_quorum_met`.
7. Add future-round buffers keyed by target and body hash.
8. Wire `RoundSkipCertificate` validation into runtime round-jump logic.
9. Add assist-threshold logic that emits the local future-round vote only when
   the vote can complete a compatible certificate.
10. Wire `DataDisseminationManifest` into runtime data-dissemination
    carry-forward checks for future-round assist.
11. Add observer replication-lag metrics for certified block manifests.
12. Add simulator support for `assist_after_skipped_round` so a configured
    dispatch round can hang, produce a future-round assist, and expose
    `future_round_assists`, `future_round_skipped_messages`,
    `future_round_dropped_local_blocks`, and
    `future_round_carried_forward_blocks` counters.
13. Add stage tests where one peer accepts a connection and never responds.

## Tests

Minimum tests before implementation is considered complete:

- a silent TCP server causes `send_wire_request` to return timeout;
- a silent client connection does not keep a server task alive forever;
- broadcast returns once quorum receipts arrive even with one silent peer;
- broadcast records timeout receipts for silent peers;
- a late but still-current message is accepted;
- a stale message after finality is rejected;
- raw future-round messages are buffered but do not force advancement;
- `advance_threshold - 1` compatible future-round messages trigger the local
  assist vote when the local vote can complete a certificate;
- `advance_threshold - 1` compatible future-round messages do not advance local
  state until the local vote is included or another full certificate arrives;
- timeout/skip assist emits only a round-change vote with the last certified
  state, not an unvalidated future-round data vote;
- data-bearing assist is rejected until the node fetches and validates the
  body, dissemination evidence, and parent certificate chain;
- skip assist is rejected when the last certified branch lacks data
  dissemination evidence;
- a node holding required certified data gossips or serves that data before, or
  together with, its future-round assist;
- future-round descendants cannot be certified from a parent whose data
  replication target is unmet or not repairably carried forward;
- if the first fanout round is skipped before the local block reaches the
  replication target, the local block is dropped from the assisted future
  branch;
- if a later round is skipped after first fanout, the local block is carried
  forward through the certified block manifest and remains eligible for
  repair/reconciliation;
- observer reports replication lag for certified data that has not yet reached
  every non-faulty active node;
- an assisting node still serves previous certified data and lower-round repair
  evidence while refusing new conflicting lower-round votes;
- a future-round quorum certificate forces advancement to that round;
- unsupported high future-round messages are buffered and trigger certificate
  fetch, not unbounded round jump;
- a timeout/skip certificate forces advancement without committing a lower-round
  body;
- `2q/3 - 1` future-round messages are insufficient when below the configured
  supermajority threshold;
- slow lower-round nodes are marked lagging/recoverable, not faulty, absent
  cryptographic or membership evidence;
- repeated timeout observations mark a peer suspect but do not remove it;
- membership removal still requires threshold evidence;
- reconnect succeeds only through ping/catch-up/admission quorum.

## Open Questions

- Should default deadlines be global environment variables, per-runtime config,
  or both?
- Should broadcast abort unfinished tasks or let them complete detached for
  telemetry?
- What suspicion threshold should move a peer from `Suspect` to
  `DropCandidate` in trusted mode?
- Should repair/reconciliation use hedged requests by default, or only after a
  timeout observation?
