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
context, and quorum size. The default quorum size is six. Supermajority checks
use two-thirds-plus-one and reject duplicate or unknown senders.

## v2 Prefill Dispatch

In v2, each node first dispatches its local block to the peers it will meet
across future rounds. This prefill stage is not a consensus decision; it
improves availability before verified rounds begin.

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

Trusted mode is for private known-member deployments. It can skip some
signature checks for dispatch throughput, while still enforcing sender,
membership, hash, and Merkle gates.

## Consensus Groups

`ConsensusGroupId` lets one process host a root network plus purpose-specific
subnets. Each group has separate membership, local block queue, epoch chain, and
application-state payloads.
