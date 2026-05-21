# Protocol Stage Checklist

This is the working checklist for closing the current protocol gaps one stage
at a time. A stage is not considered complete just because code exists: it
needs executable tests and a written proof sketch for the safety and progress
properties it claims.

## Completion Standard

Each stage should land with:

- **Spec:** the intended state transition, accepted inputs, rejected inputs,
  and produced outputs are documented.
- **Safety proof sketch:** why invalid, stale, forged, equivocated, or
  out-of-quorum inputs cannot move honest local state into an invalid outcome.
- **Progress proof sketch:** under explicit timing and fault assumptions, why
  honest nodes can advance to the next stage or conclude failure/recovery.
- **Unit tests:** pure data-structure and transition tests, including negative
  cases.
- **Runtime tests:** `NodeRuntime` tests that prove deployable-node state is
  changed only by valid messages.
- **TCP tests:** end-to-end tests for the wire path when the stage is exposed
  over `WireRequest`.
- **Model tests:** deterministic in-memory or `blossom-sim` tests for multi-node
  convergence and adversarial delivery cases.

Proof sketches can live in this document first. If they grow large, split them
into stage-specific files under `docs/proofs/`.

## Working Order

1. Wire identity and signature binding
2. Membership and topology
3. Block formation
4. Dispatch
5. Echo and message matrix
6. Verification
7. Proposal
8. Commit
9. Epoch advancement and finality
10. Recovery, restart, and restate
11. Transaction validation and ledger integration
12. Discovery and durable storage

The first stages intentionally front-load message authenticity. Later stages
depend on message fields being cryptographically bound and semantically
validated.

## Cross-Stage: Bounded Awaits And Future-Round Assist

**Status:** protocol artifact and simulator gate implemented; runtime round
driver wiring remains open.

`src/round_skip.rs` now contains the shared future-round assist decision,
data-dissemination manifest, signed round-skip vote, and round-skip certificate
validation logic. The simulator imports the same decision function for
skipped-round workloads, so the model no longer has a private copy of this
rule. The proof sketch lives in
[`docs/proofs/round-skip-carry-forward.md`](proofs/round-skip-carry-forward.md).

**Implemented checks:**

- First fanout skipped before local data replication yields
  `AssistDroppingLocalBlock`.
- Later skips after first fanout preserve local blocks through a carried
  manifest.
- Later skips with insufficient local replica evidence return
  `ServeDataBeforeAssist`; they do not drop the block by default.
- Carried manifests require per-block replica evidence, and repair can
  reconstruct the full canonical data set from distributed replicas.
- Manifest/certificate validation can require `f + 1` replica holders per
  carried block for Byzantine-safe trustless production.
- Missing skip certificates buffer rather than advancing.
- Data-bearing future-round assist requires validated future body data.
- Round-skip certificates count only distinct current-validator signatures.
- Duplicate, out-of-membership, stale, and mismatched votes do not satisfy the
  skip threshold.
- `blossom-sim` emits skipped-message, assist, dropped-local-block, and
  carried-forward counters for the observer and stage CSV path.
- `blossom-sim` reports `data_available_nodes` and `data_unavailable_nodes`,
  and long repair/reconnect checks fail if nodes converge by hash without
  reconstructing canonical block data.
- `blossom-sim` reports `valid_local_blocks`,
  `intentionally_dropped_local_blocks`, and `incorrectly_lost_local_blocks`.
  Runtime reconciliation fails if any valid non-intentionally-dropped local
  block loses all active replica sources.
- Reconciliation can reconstruct a canonical block set from partial per-node
  replicas; a node's own local block remains usable as a repair source even if
  that node is not yet a full data holder.

**Current gaps:**

- `NodeRuntime` does not yet buffer future-round messages or emit a local
  assist vote when its vote completes a compatible certificate.
- Runtime round-jump logic does not yet consume `RoundSkipCertificate`.
- Runtime data repair does not yet consume `DataDisseminationManifest` as the
  canonical catch-up proof for future-round branches.

**Proof obligations:**

- Future-round advancement must require a certificate bound to the current
  epoch, nonce, source round, target round, and manifest hash.
- Slow lower-round nodes must be classified as lagging/recoverable unless
  separate threshold evidence proves membership removal.
- A first-fanout skip must never certify private local data that has not entered
  the dissemination tree.
- A valid block that has entered the dissemination tree must remain available
  from at least one active replica until all active correct nodes can reconstruct
  the canonical block set.
- Trustless round-skip admission must validate the certificate against the
  concrete manifest and use a replica threshold high enough to leave at least
  one honest source under the configured Byzantine bound.

## Stage 1: Wire Identity And Signature Binding

**Status:** first verification gate implemented.

The message signature domain includes sender, last epoch, nonce, round, and
message kind. Protocol bodies now bind their semantically relevant fields for
the current message surface, and echo recovery messages verify signatures on
runtime intake. Runtime message admission is documented in
[`docs/proofs/message-admission.md`](proofs/message-admission.md).

**Implemented checks:**

- `VerificationBody` signatures bind both `blocks_hash` and the embedded block
  set.
- `ProposalBody` signatures bind the consensus decision, approved block set,
  approved hash, verification signatures, signature-tree set, and
  signature-tree hash.
- `CommitBody` signatures bind the consensus decision and inserted
  signature-tree keys.
- `EchoRequest` and `EchoReDispatch` signatures bind requested or redispatched
  block sets and are verified by `NodeRuntime`.
- `EchoReDispatch` runtime intake verifies redispatched block integrity before
  acknowledging the message.
- Runtime consensus-message intake now rejects stale messages for
  finalized-but-known epoch targets; accepted signed messages must address the
  current chain tip and next nonce.
- TCP coverage signs and accepts `EchoRequest` and `EchoReDispatch` over the
  real wire path.
- TCP-level adversarial coverage rejects non-members and wrong-round members
  for every consensus message kind before quorum accounting can change.

**Remaining gaps:**

- Hot/cold dispatch equivalence should be expanded into a single table-driven
  test covering sender, epoch, nonce, round, duplicate, and signature errors.
- Trusted mode needs a short written proof sketch of the extra assumptions
  created by skipping signatures.

**Proof obligations:**

- A signed message has exactly one protocol interpretation for its stage.
- A message signed for one epoch, nonce, round, kind, group, or body cannot be
  replayed as another.
- Trusted mode must be an explicit exception with documented membership and
  transport assumptions.

## Stage 2: Membership And Topology

**Status:** first verification gate implemented.

The base-six quorum schedule and supermajority threshold exist and are tested
for ideal sizes such as 6, 36, and 216. Additional tests now cover
determinism, self inclusion, sorted/deduplicated quorums, bounded overflow
quorum size for non-ideal node counts, and agreement among all members of a
round group. The trustless threshold proof is documented in
`docs/proofs/thresholds.md`, and executable tests now cover quorum intersection,
the unsafe `q - 1` boundary, Byzantine population limits, and repair/reconnect
quorum boundaries. Membership pruning tests now prove that a verifier set
derived from committed supermajority removal evidence still yields compatible
round schedules for every retained validator.

**Current gaps:**

- Non-ideal network sizes can produce quorums larger than six by appending
  nodes beyond the optimal base-six prefix. Tests now pin this as a
  deterministic policy, but the proof text still needs to state why the policy
  is acceptable or whether production should reject those sizes.
- Production discovery is local address-book registration, not a DHT or durable
  membership protocol.

**Tests to add next:**

- TCP-level tests that drive a committed membership-pruned epoch and prove all
  remaining nodes independently derive the same next-round schedule.

**Proof obligations:**

- Honest nodes derive the same quorum schedule from the same epoch body.
- Each round's membership and supermajority threshold preserve the intended
  fault bound; see `docs/proofs/thresholds.md`.
- Any non-ideal-size policy is deterministic and cannot strand validators
  outside all progress paths.

## Stage 3: Block Formation

**Status:** first verification gate implemented.

Signed blocks, local queues, nonce checks, duplicate rejection, application
state limits, and opaque transaction commitment exist. Full ledger semantics do
not.

**Implemented checks:**

- `submit_block` rejects wrong last epoch, wrong nonce, invalid block hash or
  Merkle root, bad signatures, duplicate nonces, full queues, and wrong
  registered block-service identity.
- Local block queue tests pin stale-block dropping, future-block preservation,
  wrong-validator rejection, unsigned trusted-mode enqueue boundaries, and
  close failure without losing the pending build block.
- `dispatch_local_block` now has a regression test proving the emitted
  dispatch contains a header-signed body commitment and a block targeted to the
  current epoch/nonce.
- A TCP cluster test proves every validator can submit and dispatch its own
  block for the same epoch hash and nonce, with distinct validator keys and
  block hashes.

**Current gaps:**

- The crate does not implement transaction pre-validation against ledger state.
- Block close policy is count-based in the runtime config, while the paper also
  discusses byte caps.
- Opaque transactions are committed but not semantically validated.

**Tests to add next:**

- Tests for byte-cap block closing once a block-byte cap is introduced.
- End-to-end tests that commit all validators' same-target blocks into the next
  epoch body once the round driver exists.

**Proof sketch for the current gate:**

`submit_block` checks the target epoch hash and nonce before enqueueing, then
applies the active trust-mode integrity rule. In verified mode, the block hash
must equal the canonical body hash, the Merkle root must match the transaction
set, and the validator signature must verify over that hash. In trusted mode,
only the explicit unsigned-integrity path can skip the signature. Since the
queue admits at most one block per nonce and preserves future blocks instead of
silently retargeting them, a locally accepted block is tied to one validator,
one last epoch, and one nonce.

**Proof obligations:**

- A locally accepted block is tied to exactly one validator, last epoch, and
  nonce.
- A block hash commits all consensus-relevant block data.
- Empty blocks and application-state-only blocks preserve deterministic epoch
  hashing.

## Stage 4: Dispatch

**Status:** first verification gate implemented.

Dispatch construction, signature verification, sender membership checks,
duplicate rejection, hot frame decoding, pending raw-byte caps, and block
verification exist.

**Implemented checks:**

- `DispatchBody::validate` rejects block-set and signature-tree hash
  mismatches.
- `NodeRuntime` validates dispatch body commitments, block epoch/nonce target,
  block integrity, and signature-tree integrity before a dispatch can consume
  the sender's pending-dispatch slot.
- `TempQuorum::verify` skips wrong-target blocks even when pending dispatches
  are inserted directly in lower-level tests.
- Runtime tests prove bad body hashes, invalid block payloads, and wrong block
  targets are rejected before sender accounting, so a later valid dispatch from
  the same sender is still accepted.
- Accepted decoded and hot dispatches now update the quorum message matrix as
  well as pending dispatch and sender accounting. Runtime tests assert the
  sender/receiver matrix cell and pending slot agree.
- Runtime dispatch intake records locally verified dispatch blocks so later
  verification votes can only count block sets this node has actually checked.
- Local dispatch creation records the node's own verified dispatch block set
  into quorum state, so finality can include locally formed blocks through the
  same verified-block path as peer dispatches.

**Current gaps:**

- Dispatch intake queues pending dispatches and updates the message matrix, but
  does not automatically trigger echo or verification.
- The deployable node does not broadcast local dispatches to all quorum peers.
- Accepted dispatches are not yet part of an end-to-end round driver.

**Tests to add next:**

- End-to-end tests where all members of a quorum receive all honest dispatches.
- Table-driven hot/cold adversarial tests for duplicate dispatch, wrong round,
  wrong epoch, and oversized raw dispatch backlog.

**Proof sketch for the current gate:**

An accepted dispatch first has a valid message signature for the sender, epoch,
nonce, round, message kind, and dispatch commitments. The sender must be a
member of that round. The body commitment must match the block map and
signature-tree map; every included block must verify under the active trust
mode and must target the same last epoch and nonce as the dispatch header.
Only after those checks does runtime sender accounting record the dispatch, so
malformed traffic cannot inflate quorum progress or block a valid retry from
the same sender.

**Proof obligations:**

- An accepted dispatch can only add valid, epoch-targeted blocks from a current
  round member.
- Duplicates and malformed dispatches cannot inflate observed quorum progress.
- Hot and cold dispatch encodings are semantically equivalent.

## Stage 5: Echo And Message Matrix

**Status:** first matrix intake gate implemented.

The `MessageMatrix` data structure exists and can model dispatch and echo
observations. Runtime dispatch and echo-response intake now update the matrix
for valid quorum members and reject unknown echo subjects before matrix state
changes. Matrix unit tests now cover all-honest pass, missing dispatch,
delayed dispatch completion, false echo, and unknown-peer cases.

**Current gaps:**

- `EchoRequest` and `EchoReDispatch` do not request, validate, or insert
  missing blocks.
- There is no wait policy for distinguishing delayed, missing, and faulty
  peers.

**Tests to add:**

- `blossom-sim` tests that delayed dispatches can recover through echo request and
  redispatch.

**Proof obligations:**

- Matrix status reaches pass only when a supermajority has enough consistent
  dispatch/echo evidence.
- Echo evidence cannot make a node pass a block set it has not verified or
  cannot recover.
- Timeout policy is conservative enough to avoid premature honest-peer
  pruning under the stated synchrony bound.

## Stage 6: Verification

**Status:** first verification intake gate implemented.

Verification message types and counters exist. Runtime records votes by hash.

**Implemented checks:**

- Runtime validates that `VerificationBody.blocks` hashes to `blocks_hash`
  before counting.
- Runtime requires the verification body to match the receiving node's locally
  verified block set before counting.
- Repeated votes by the same sender replace the stored message without
  inflating old counts.
- Unit tests cover mismatched verification body commitments and sender
  replacement accounting, and runtime tests reject verification votes for
  unverified block sets, replace an equivocating sender's vote, and require
  distinct senders for a supermajority.

**Current gaps:**

- Verification intake still does not emit or drive the next proposal stage.

**Tests to add:**

- End-to-end round-driver tests that emit verification only after dispatch
  recovery and block verification complete.

**Proof obligations:**

- A verification vote is counted for exactly one verified block set.
- Byzantine equivocation cannot raise multiple block hashes above threshold
  through duplicate sender accounting.
- Honest nodes that verified the same block set eventually identify the same
  consensus hash.

## Stage 7: Proposal

**Status:** first proposal proof gate implemented.

Proposal message types and counters exist. Runtime counts approved hashes.

**Implemented checks:**

- Runtime validates consensus proposals for approved block/hash consistency and
  signature-tree hash consistency before counting.
- Proposal signatures bind the consensus flag, approved blocks, approved hash,
  verification signatures, and signature-tree commitments.
- Proposal sender replacement adjusts counts instead of accumulating
  equivocations.
- Unit tests cover missing approved blocks and mismatched proposal proof
  commitments.
- Runtime now accepts true consensus proposals only when they reference the
  node's locally verified block set and carry a distinct quorum supermajority
  of valid verification signatures from quorum members. The proof sketch lives
  in [`docs/proofs/proposal.md`](proofs/proposal.md).
- TCP coverage now sends a true consensus proposal with an embedded
  supermajority verification proof over the real wire path.

**Current gaps:**

- Proposal intake still does not emit or drive the commit stage.
- False proposals are counted as negative votes, but the runtime does not yet
  preserve a locally provable true supermajority against later false proposal
  scheduling because the deployable round driver is not implemented.

**Tests to add:**

- Model tests where one proposal wins only when backed by distinct verifier
  signatures across adversarial delivery schedules.
- End-to-end round-driver tests that emit proposal only after verification
  consensus exists and then drive commit.

**Proof obligations:**

- A proposal for consensus true is accepted only when it proves a valid
  verification supermajority. **Implemented for runtime intake.**
- A proposal for consensus false cannot erase an already provable true
  supermajority.
- Distinct-sender accounting is stable under retries and equivocation.

## Stage 8: Commit

**Status:** first commit threshold gate implemented.

Commit messages are accepted and commit senders are recorded.

**Implemented checks:**

- `consensus` is signed. **Fixed.**
- Runtime marks the commit decision visible only after a distinct quorum
  supermajority of accepted true commit votes. Duplicate sender commits cannot
  inflate the threshold, and a later false vote from the same sender removes
  that sender from the true-vote set. The proof sketch lives in
  [`docs/proofs/commit.md`](proofs/commit.md).
- Runtime rejects true commits unless the receiver has already accepted a true
  proposal supermajority for the same quorum.

**Current gaps:**

- Commit does not yet trigger round advancement or final epoch creation in the
  deployable runtime.

**Tests to add:**

- End-to-end tests where a quorum reaches commit and advances only once.

**Proof obligations:**

- A commit decision reflects a valid proposal outcome from a supermajority.
- A single Byzantine commit cannot advance honest local state. **Implemented
  for runtime commit threshold visibility.**
- False commit, true commit, and missing commit outcomes are deterministic.

## Stage 9: Epoch Advancement And Finality

**Status:** first runtime finality gate implemented.

`LocalState::advance_epoch` exists and is unit-tested directly. `NodeRuntime`
now calls it when a locally valid true commit supermajority is reached.

**Implemented checks:**

- Runtime finality is downstream of local dispatch verification, verification
  proof, proposal supermajority, and true commit supermajority.
- A true commit supermajority triggers `LocalState::advance_epoch` for the
  message's last epoch, nonce, and round.
- Runtime tests prove a valid proposal plus commit supermajority creates the
  next epoch and carries the locally verified block set forward. The proof
  sketch lives in [`docs/proofs/finality.md`](proofs/finality.md).

**Current gaps:**

- No TCP cluster test yet completes all quorum rounds and finalizes the same
  epoch across all honest nodes.
- New epoch signatures are structurally present but not integrated into a full
  finality proof path.
- The current `blossom-sim` convergence model computes hashes from block-set unions, not
  from runtime-driven dispatch/echo/verification/proposal/commit state.
- `blossom-sim-epoch-chaos` emits a stage-progress CSV for modeled
  checkpoints: block formation, topology selection, dispatch rounds, recovery
  rounds, and finality.

**Tests to add:**

- A 36-node deterministic convergence test where every node starts with one
  block and all nodes finalize the same 36-block epoch.
- Runtime tests that multi-round advancement moves from round 0 to round 1 and
  then creates exactly one new epoch.
- Failure tests for no consensus, partial consensus, and mismatched nonce or
  last epoch.

**Proof obligations:**

- Honest nodes that complete all rounds with the same verified block set
  compute the same epoch hash.
- Epoch advancement is monotonic by nonce and cannot skip or replay epochs.
- Failed consensus produces a deterministic recovery/restate input.

## Stage 10: Recovery, Reconciliation, Restart, And Restate

**Status:** first reconciliation model defined.

`blossom-sim` has a restart/catch-up model based on epoch summaries and a
block-set reconciliation fallback for cases where no certified summary quorum
exists. The written process lives in
[`docs/protocol-reconciliation.md`](protocol-reconciliation.md). Progress
assumptions and executable liveness coverage are tracked in
[`docs/proofs/progress.md`](proofs/progress.md).

The protocol wire does not yet expose the paper's second recursion:

```text
Appraisal -> Echo -> Verification -> Proposal -> Request -> Commit
```

**Current gaps:**

- No `Appraisal` message.
- No protocol-level recovery `Request` distinct from availability-gossip
  payload fetches.
- No concrete `ReconcileAppraisal`, `ReconcileRequest`, `ReconcileResponse`, or
  `ReconcileCommit` wire messages.
- `WireRequest::GetBlock` is block-service-facing and consensus nodes do not
  serve it.
- Restate after failed global finality is modeled in `blossom-sim` but not
  implemented in `NodeRuntime`.
- The sim abstracts the rebuilt-body commit certificate as the canonical
  modeled epoch hash; runtime still needs certificate validation.

**Defined reconciliation rule:**

- Freeze speculative advancement at the lowest unresolved nonce.
- Find the highest common durable checkpoint backed by a supermajority commit
  certificate.
- Try summary catch-up only when the summary carries a valid certificate chain.
- If no certified summary quorum exists, collect signed block manifests and
  blocks for the checkpoint parent and unresolved nonce.
- Exclude equivocal validator blocks deterministically and commit the rebuilt
  body through verification, proposal, and commit.
- Restate local speculative descendants on top of the committed rebuilt epoch.

**Tests to add:**

- Runtime and TCP tests for reconciliation message signature binding and body
  validation.
- Runtime and TCP tests for appraisal, request, response, and recovery commit.
- Chaos tests where late or dropped primary messages diverge nodes, then
  reconciliation converges them. The first deterministic `blossom-sim` test now
  covers an unavailable summary quorum that is repaired by signed block-set
  reconstruction.
- Deterministic progress tests now cover partial synchrony, full partitions
  that heal after several simulator ticks, and Byzantine churn below the
  threshold.

**Proof obligations:**

- A recovering node adopts only a state backed by a supermajority summary or
  equivalent proof.
- Recovery transfers enough data to reconstruct the committed block set before
  local finality.
- Restate cannot be triggered by a minority to roll back an honest finalized
  epoch.
- Two conflicting reconciliation commits for the same parent and nonce require
  an honest verifier to sign conflicting body hashes under the standard
  less-than-one-third Byzantine assumption.
- Under eventual synchrony, an unresolved nonce remains pending and eventually
  reconciles before later durable descendants are formed.

## Stage 11: Transaction Validation And Ledger Integration

**Status:** not implemented in this crate.

Blossom commits opaque transaction payloads. Application-owned semantics,
ledger mutation, derivative epoch hashing, transaction tagging, and historical
queries remain outside the crate.

**Current gaps:**

- No application ledger adapter.
- No transaction pre-validation or final validation rules.
- No derivative epoch hash over validated transaction outcomes.
- No append-only ledger update or historical query implementation.

**Tests to add:**

- Ledger-adapter contract tests with deterministic transaction ordering.
- Invalid transaction tests proving invalid bodies do not change ledger state
  but still produce deterministic outcomes.
- Multi-node tests where all honest validators apply the same epoch body and
  derive the same ledger hash.

**Proof obligations:**

- Given the same ordered epoch block set and deterministic application rules,
  all honest validators compute the same ledger state.
- Invalid transaction handling is deterministic and cannot fork honest state.
- Historical query paths are derived from committed ledger data.

## Stage 12: Discovery And Durable Storage

**Status:** outside the current protocol core.

The node has local address-book registration and in-memory state. Production
membership discovery, persistent epoch storage, and replay after restart are
not implemented.

**Current gaps:**

- No decentralized discovery/DHT path.
- No durable epoch/block store in the deployable node path.
- Restart catch-up is modeled in `blossom-sim` but not connected to persisted state.

**Tests to add:**

- Restart tests that reload committed epochs and reject stale messages.
- Discovery tests once a production membership path exists.
- Durability tests for partial writes, corrupted state, and idempotent replay.

**Proof obligations:**

- Restarted nodes recover exactly the last committed local state or enter a
  safe catch-up mode.
- Discovery cannot silently change the verifier set outside an epoch transition.
- Durable storage preserves the hash commitments used by consensus proofs.

## Immediate Next Step

Next, continue Stage 4 into Stage 5. The useful gate now is a multi-node test
where every validator contributes one block for the same epoch target, all
valid dispatches update pending quorum state consistently, and echo/matrix
state advances from those dispatch observations.

## Verification Commands

Use these as the current stage gates:

```sh
cargo test signature
cargo test echo_recovery
cargo test quorum_
cargo test receive_dispatch_rejects
cargo test --test e2e_tcp protocol_message_variants_are_accepted_over_tcp
cargo test -p blossom-sim
cargo test --workspace
```

For model and fault-injection work, prefer the renamed simulation environment:

```sh
./benchmarks/scripts/run-sim-hermetic.sh
./benchmarks/scripts/run-sim-fuzz.sh
./benchmarks/scripts/run-sim-container.sh sim
./benchmarks/scripts/run-epoch-chaos.sh
```
