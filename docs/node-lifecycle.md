# Node Lifecycle: Registration, Dropping, And Reconnect

This document describes the current Blossom node lifecycle as implemented in the
protocol crate and modeled in the deterministic simulator. It separates plain
address-book registration from signed public-node admission because those two
paths have different safety properties.

## Implementation Map

- `src/admission.rs` defines the signed public-node admission proof.
- `src/address_book.rs` stores service endpoints keyed by `(ServiceKind,
  PubKey)`.
- `src/runtime.rs` owns the local consensus state, address book, block queue,
  encounter evidence, and membership-pruning policy.
- `src/tcp.rs` exposes `WireRequest::RegisterService`, `WireRequest::Ping`,
  consensus message intake, and node status over TCP.
- `src/state.rs` advances epochs and applies the verifier-removal reducer to
  committed blocks.
- `src/membership.rs` derives deterministic verifier-removal decisions from
  committed encounter evidence.
- `crates/blossom-sim/src/epoch.rs` models faulty-node dropping, reconnect
  admission, replay attempts, stale proofs, Sybil attempts, duplicate votes,
  partitions, and reconnect DoS pressure.

## Service Registration And Public Joins

`WireRequest::RegisterService(ServiceRegistration)` has two modes:

- `ServiceRegistration::Service(Service)` registers reachability metadata only.
- `ServiceRegistration::NodeAdmission(NodeAdmission)` registers a consensus
  service and stages a signed public-node join proof for the next local block.

Plain service registration calls `NodeRuntime::register_service`, which inserts
the service into the local `AddressBook`. The address book key is
`(service.kind, service.public_key)`, so registering the same kind and key again
replaces the previous endpoint and returns it in `AddressBookUpdate.previous`.

If the registered service is a block service, the TCP handler announces the
node's next expected block nonce to that service and returns the announced nonce
in `AddressBookUpdate.nonce_announced`.

Plain service registration does not:

- prove ownership of `service.public_key`;
- broadcast the service to other nodes;
- add the public key to the epoch verifier set;
- bypass consensus-message membership checks;
- create a durable discovery record.

Signed public-node admission is the real join path. A joining node signs a
`NodeAdmissionBody` that binds its node identity, consensus service endpoint,
parent epoch hash, and next nonce. The receiving validator verifies the
signature, registers the endpoint, stages the admission into its local block
queue, and reports the staged identity in `AddressBookUpdate.admitted_node`.

The join is not active at registration time. It becomes verifier membership only
when a supermajority of distinct current verifiers carry the same signed
admission body in committed blocks for the next epoch. This keeps public joins
deterministic across the cluster: all nodes derive the same membership update
from the same committed block set, and one Byzantine verifier cannot add a node
alone.

## Validator Membership

Verifier membership is the set stored in `EpochBody.verifiers`.

The current runtime creates membership in three ways:

1. Genesis provisioning: `genesis_epoch(...)` or
   `genesis_epoch_for_group(...)` creates the initial verifier set.
2. Public join admission: at epoch advancement, committed signed
   `NodeAdmission` proofs can add new validators.
3. Membership pruning: at epoch advancement, committed encounter evidence can
   remove validators when `ConsensusNodeRemovalPolicy` is enabled.

For brand-new public nodes, `RegisterService(NodeAdmission)` is intentionally
open: any node that owns a key can ask to join. Existing verifiers still control
whether the admission enters consensus, because only committed blocks from
current verifiers are considered by the membership reducer, and duplicate
admission votes from the same verifier count once.

## Consensus Message Admission

Registering a consensus service gives the local node an endpoint it can dial,
but incoming consensus messages still pass the runtime admission gate:

1. The message must reference the current chain tip and next expected nonce.
2. In verified mode, the signature must bind sender, epoch hash, nonce, round,
   message kind, and body commitment.
3. The sender must be a current verifier assigned to the addressed round.
4. The message body must pass stage-specific validation before quorum accounting
   changes.

Malformed, stale, duplicate, or out-of-membership messages fail before they can
inflate dispatch, verification, proposal, commit, epoch-started, or recovery
state. This gate is documented in
[`docs/proofs/message-admission.md`](proofs/message-admission.md).

## Dropping A Faulty Validator

Dropped-node behavior is evidence-based and disabled by default in the runtime.
When enabled, it happens only as part of epoch advancement.

The process is:

1. During consensus, an observer records signed encounter evidence for a subject
   that missed an expected signature or produced an invalid signature.
2. The observer includes those records in its next block.
3. The block is verified and committed into the next epoch candidate.
4. `LocalState::advance_epoch` calls `apply_epoch_membership_transition`.
5. `derive_consensus_node_removal_plan` counts only valid records from current
   verifiers about current verifier subjects for the exact epoch and nonce.
6. If the subject has enough distinct observer evidence, the subject is removed
   from the next epoch verifier set.

Evidence that does not count:

- unknown observers or subjects;
- self-accusations;
- stale epoch or nonce records;
- invalid encounter signatures;
- duplicate records from the same observer for the same subject;
- records that were observed but not committed in the epoch block set.

`ConsensusNodeRemovalPolicy::supermajority()` requires at least the current
verifier-set supermajority, removes at most one verifier per epoch by default,
and preserves the configured minimum verifier count. A deployment may raise the
observer threshold, but it cannot lower the threshold below supermajority.

## Reconnect And Rejoin

The reconnect process is currently implemented in the simulator as the target
protocol for reconnecting a dropped validator. The production runtime now has
the signed `NodeAdmission` block-carried join primitive for adding a key back to
membership; the fuller reconnect policy still needs catch-up proof and admission
quorum wiring before a dropped trustless validator should be allowed to rejoin
automatically.

The modeled process is:

1. The dropped node keeps its original identity key. A different key is rejected
   as a Sybil/identity mismatch.
2. The candidate pings active peers. In verified mode, the ping quorum must meet
   the Byzantine-safe supermajority threshold for the active peer set.
3. If enough pings succeed, the candidate gathers catch-up proofs for the current
   canonical checkpoint.
4. Stale, replayed, duplicate, or partition-minority evidence is rejected.
5. Active peers then cast admission votes.
6. If the approval quorum succeeds and the per-epoch reconnect rate limit allows
   it, the node rejoins the active set and emits
   `membership_reconnect/node_reconnected`.

Trusted mode models accidental faults in a known private membership set and can
use smaller operational repair quorums. Verified mode is the trustless path: it
rejects unsafe low quorums, Byzantine populations above `floor((n - 1) / 3)`,
stale catch-up proofs, replayed evidence, duplicate votes, and identity swaps.

## Telemetry And Tests

Dropping and reconnect are observable through simulator telemetry:

- `membership_pruning/node_dropped`
- `membership_reconnect/peer_ping`
- `membership_reconnect/catchup_proof`
- `membership_reconnect/admission_vote`
- `membership_reconnect/node_reconnected`

The observer aggregates dropped and reconnected node counts by node identity.
The relevant executable coverage includes:

- `address_book_registration_announces_nonce_to_block_service`
- `advance_epoch_removes_node_with_supermajority_failure_evidence`
- `supermajority_evidence_plans_node_removal`
- `stale_duplicate_or_unknown_evidence_does_not_count`
- `trusted_dropped_nodes_reconnect_after_peer_ping_and_admission_vote`
- `trustless_dropped_nodes_reconnect_with_byzantine_safe_quorums`
- `byzantine_admission_abuse_cannot_approve_stale_node`
- `byzantine_replayed_reconnect_evidence_does_not_satisfy_ping_quorum`
- `byzantine_duplicate_reconnect_votes_are_deduplicated`
- `partitioned_reconnect_waits_until_merge`
- `many_dropped_nodes_reconnect_are_rate_limited`
- `reconnect_rejects_sybil_identity_attempts`

The threshold and failure-boundary proofs live in
[`docs/proofs/thresholds.md`](proofs/thresholds.md) and
[`docs/proofs/failure-boundaries.md`](proofs/failure-boundaries.md).

## Public Readiness Boundary

Current production-facing code supports static genesis membership, plain service
registration, signed public-node admission through committed blocks,
consensus-message admission, evidence-based membership pruning, and
simulator-backed reconnect validation. Before public trustless deployment,
Blossom still needs a reconnect policy that requires catch-up proof and an active
validator admission quorum for previously dropped nodes, plus rate limits for
high-volume public join attempts.
