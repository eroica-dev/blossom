# Protocol Overview

Blossom commits opaque application bytes into signed node-local blocks. It does
not parse transactions or define application semantics.

## Nodes And Validators

Each validator is identified by a `PubKey` and advertised service endpoint.
Genesis membership is created with `genesis_epoch(...)` or
`genesis_epoch_for_group(...)`.

Public joins use signed `NodeAdmission` proofs carried by committed blocks.
Plain service registration updates the local address book; it does not change
validator membership by itself.

## Quorums And Rounds

Blossom derives deterministic sub-quorums from the current validator set, epoch
context, and configured branching factor. `BLOSSOM_QUORUM_SIZE` accepts integers
`q >= 3` divisible by three and defaults to six. `--quorum-size` takes
precedence over the environment.

The configured value is a branching factor, not a global finality threshold.
The effective size is `min(q, validator_count)`, local thresholds derive from
the selected committee, and global finality derives independently from the
complete validator set. The resolved value is committed in consensus
parameters. A joining or restored node must match the committed value; changing
the process environment cannot change a live network.

Supermajority checks use the ceiling of two thirds and reject duplicate or
unknown senders. Topology and threshold calculations use checked integer
arithmetic.
In the final round, every validator sends its exact-hash commit share to a
deterministically selected bounded collector committee. A collector may
publish only after assembling signatures from a supermajority of the complete
previous verifier set. Signed epoch-start messages are bounded hints, not
proofs: a lagging validator changes committed state only after fetching and
validating the corresponding `CertifiedEpochSuffix`. Publishers retain the
exact signed hint and retry only its unacknowledged validator recipients, so a
temporary partition cannot permanently strand a validator after healing.

## v2 Prefill Dispatch

In v2, each node first dispatches its local block to the peers it will meet
across future rounds. This prefill stage is not a consensus decision; it
improves availability before verified rounds begin.

The exact signed prefill dispatch is retained and retried only to routed peers
that have not acknowledged it. Manual drivers must complete this stage before
ordinary dispatch. Dispatch production is single-writer and idempotent for a
sealed round, and application admission after the local dispatch is sealed
fails closed.

Every network driver tick is bound to the epoch target captured when the tick
begins. If certified finality advances the runtime while the tick awaits a
network response, the remaining stages stop instead of resuming against the
next epoch. If a verification or proposal broadcast is only partially
delivered, later ticks replay the exact original signed message.

Later rounds still verify, propose, and commit the epoch view. Prefilled blocks
seed local availability, but canonical state changes only after signed quorum
evidence and deterministic reconciliation agree.

## Recovery And Reconciliation

The runtime includes bounded recovery paths for echo redispatch, manifest block
repair, round-skip assist, catch-up from committed epoch announcements, and
reconcile commits backed by current-validator supermajority proof.

## Trusted And Trustless Modes

The default path is trustless: signed blocks, signed messages, SHA-256
commitments, fair block ordering, membership gates, and Byzantine-safe
thresholds.

Trusted Global Blossom is for private known-member networks with at least six
logical members. It retains sequential quorum ordering while using a durable
confirmation log, append-only origin continuity, and service-facing recovery
status. The optional `trusted-checkpoint-dag` profile adds append-only DAG
dissemination and repair beneath sequential quorum checkpoints. The trusted
mode changes the threat model; it does not weaken hash, membership, continuity,
or durability validation.

Small-cluster HA is a separate trusted protocol and wire profile:

- `high-availability` supports 2–7 fixed identities for leaderless
  active-active replication using fixed slots and strict majorities.
- `active-passive` supports native OpenRaft leader-based replication for 2–7
  physical nodes, including learners, failover, snapshots, and joint-consensus
  voter replacement.
- `parallel-networks` allows an independent Global Blossom network to order
  sealed HA references. It never combines HA and Global Blossom membership,
  voting, availability, or health.

See [Small-Cluster High Availability](high-availability.md),
[Trusted Network Durability and Recovery](trusted-network-durability.md), and
[Parallel HA and Global Blossom Networks](parallel-ha-global-blossom.md).

## Consensus Groups

`ConsensusGroupId` lets one process host a root network plus purpose-specific
subnets. Each group has separate membership, local block queue, epoch chain, and
application-state payloads.
