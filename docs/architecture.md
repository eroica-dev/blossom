# Architecture

This crate follows the Blossom protocol architecture described in the
LaTeX paper under `paper/`, with `paper/sections/protocol.tex` as the
primary reference. The paper frames Blossom as a serialized cycle with
three stages:

1. Block formation
2. Block propagation
3. Transaction validation

The current Rust extraction keeps reusable protocol logic and a compact
deployable node surface. It includes message types, deterministic quorum
selection, local consensus state, block verification primitives, the
message matrix used during propagation, address-book registration, local
block intake, and a raw TCP node process.

## Stage Map

### Block Formation

Every validator can independently receive transactions, pre-validate
them against local state, and close a local block. In this crate, that
surface is represented by:

- `src/block.rs`: signed block and opaque transaction payload primitives.
- `src/block.rs`: bounded opaque application-state payloads carried in
  the block metadata and committed by the block hash/signature.
- `src/local_block.rs`: queued block intake from the block service and
  locally closed blocks.
- `src/address_book.rs`: service registry for block, engine, relay,
  consensus, and address-book services.
- `src/runtime.rs`: next-nonce checks and signed block acceptance.
- `src/crypto.rs`: Ed25519 signing and verification.
- `src/hash.rs` and `src/nonce.rs`: deterministic identifiers used by
  blocks, epochs, and messages.

The extraction intentionally keeps transaction semantics application-owned.
`TransactionPayload` is opaque byte data: callers may provide a raw payload or
encode a versioned application struct, such as a cache key/value record, before
submitting it. Blossom computes or accepts the transaction identifier, commits
both the identifier and payload bytes into the block hash, and leaves schema
validation, ledger adapters, block size policy, and mempool behavior above this
crate or in a follow-up ledger layer.

Domain-specific codecs are expected to live above Blossom. A database module,
blockchain module, or key/value cache module can define its own versioned binary
layout and pass the encoded bytes to `TransactionPayload`. Deployments that
already compute stable operation or key hashes can pair those module payloads
with `Transaction::from_external_hash_u64` under the
`external-transaction-hashes` feature.

The optional `filtered-transactions` feature adds a second transaction
materialization mode without changing the consensus rule that every validator
commits the same ordered slots. A filtered slot commits a key hash,
application kind, sorted target set, payload commitment, payload length, and
delivery policy. Target nodes may carry the full payload; non-target nodes
carry a tombstone. Block hashing uses the canonical slot bytes rather than the
local payload view, so both materializations verify against the same Merkle root
and block hash. This is a filtered data-placement primitive, not a full privacy
claim: encryption, metadata hiding, proofs, and gossip-assisted availability
can be layered above it.

With `availability-gossip`, Blossom adds that first data-availability layer:
holders gossip signed filtered-slot availability entries, targets fetch payload
bytes by slot hash and payload commitment, and receivers verify the bytes before
storing them as local payloads. Gossip does not decide consensus truth; it only
helps a target discover where committed bytes can be fetched.

For KVCache, the useful property is that keys and commitments are relatively
stable. Dissemination can therefore be planned in rounds rather than epochs.
`ideal_push_gossip_rounds(node_count, fanout)` estimates
`ceil(log_(fanout + 1)(node_count))` rounds under ideal push gossip. Wall-clock
delay is that round count times the gossip interval, plus an operational safety
round for duplicate fan-out, scheduling jitter, and loss. For 36 nodes at
fanout 6, the ideal is 2 rounds; at a 100 ms interval, operators should expect
about 200 ms ideal dissemination and plan around roughly 300 ms with one safety
round. Payload readiness adds the target's fetch RTT, payload transfer time, and
commitment-verification time on top of metadata dissemination.

Blocks also expose a generic application-state channel. The payload is
opaque `Vec<u8>` data with a 4 KiB soft budget and an 8 KiB hard limit.
Blossom validates only the size and commits the bytes into the block hash;
version tags, parsing, compatibility, decay, and timeout behavior belong
to the application. Once an epoch commits, every validator observes the
same payloads in the same block order, and the block nonce/epoch acts as
the publication timestamp.

### Block Propagation

The paper's consensus protocol is centered on block propagation through
deterministic quorums. The canonical quorum size is six nodes, with a
two-thirds supermajority threshold. Non-consensus traffic remains normal
peer-to-peer communication, while consensus traffic uses a structured
quorum topology derived independently by every node.

The current implementation maps that layer to:

- `src/algorithm.rs`: deterministic quorum and round selection.
- `src/group.rs`: stable root/subnet consensus group identifiers.
- `src/messages.rs`: the transport enum for protocol messages.
- `src/blossom.rs`: message headers, bodies, signatures, body hashing,
  and dispatch verification helpers.
- `src/register.rs`: quorum queue and echo/message matrix state.
- `src/state.rs`: local state, temporary consensus state, temporary
  quorum state, proposal counts, verification counts, and epoch
  advancement.
- `src/wire.rs`: length-prefixed Borsh wire protocol for node and
  service requests.
- `src/tcp.rs`: reusable server/client path used by the node binary,
  harness, and end-to-end tests.
- `src/wire.rs` and `src/tcp.rs`: direct `Ping`/`Pong` liveness checks
  that target one peer and do not enter the epoch state machine.
- `src/overlay.rs`: address-book-backed fan-out and broadcast APIs for
  using Blossom's topology without running epoch consensus.
- `src/bin/blossom-node.rs`: TCP listener for block intake, message
  intake, dispatch generation, address-book updates, and state.
- `src/service_client.rs`: TCP helpers for block-service nonce updates
  and block/engine service calls.
- `src/harness.rs`: simulated cluster and mock block service used to
  exercise node behavior over real local TCP sockets.

The implemented primary propagation lifecycle is:

```text
Dispatch -> EchoResponse / EchoRequest / EchoReDispatch -> Verification -> Proposal -> Commit
```

Dispatch messages carry block data and signature-tree evidence. Echo
messages populate the quorum message matrix so a node can distinguish
missing dispatches, delayed peers, and likely faulty peers. Verification
and proposal messages aggregate the quorum's view of accepted block
sets, and commit records the outgoing result for the round.

Consensus groups let a deployment run the full root network and narrower
purpose-specific subnets in parallel. Each group has a stable
`ConsensusGroupId`, its own verifier set, local block queue, consensus
state, and epoch chain. The group id is committed into the genesis epoch
hash and therefore into all later block and message contexts through
`last_epoch`; this prevents a block or signed protocol message from being
replayed across groups with different ids. Ungrouped TCP requests target
the root group, while `WireRequest::Group { group_id, request }` routes a
request to the matching subnet hosted by the same node process.

Direct peer liveness is intentionally separate from both consensus groups
and overlay broadcast. `WireRequest::Ping(NodePing)` is a point-to-point
request that returns `WireResponse::Pong(NodePong)` with the caller's nonce
and payload echoed. It is useful for health checks, latency probes, and
connectivity tests where no block or quorum message should be created.

Plain service registration is also separate from verifier admission: a bare
`Service` is local reachability metadata in the address book. Public joins use a
signed `NodeAdmission` carried by `WireRequest::RegisterService`; the admission
is staged into the receiver's next block and becomes membership only if that
block is committed into the next epoch. The full lifecycle is documented in
[`docs/node-lifecycle.md`](node-lifecycle.md).

Trusted mode is an explicit private-cluster optimization. When
`RuntimeConfig::trust_mode` is `Trusted`, nodes assume the verifier set
was provisioned out of band and skip Ed25519 block/message signing and
verification. The runtime still checks that message senders belong to the
current round and that blocks match their content hash and Merkle root.
The epoch-depth benchmark uses this mode to model dispatch-only quorum
propagation, removing echo, verification, proposal, and commit messages
from the known-member fast path.

`insecure-fast-hash` is a separate build-time benchmark/deployment
switch for trusted environments. It replaces SHA-256 protocol
commitments with XXH3 while keeping the same 32-byte `HashType`
representation. The default build remains SHA-256, and the verified
protocol should use the default unless the operator explicitly accepts
non-cryptographic hash commitments.

### Encounter Evidence And Membership Pruning

Encounter records are the protocol's evidence layer for peer participation
failures. A validator can include signed records in its next block saying that a
subject missed an expected consensus-phase signature or produced an invalid
signature. The record is independently signed by the observer and hash-committed
inside the block body, so other validators can verify who made the claim and
which epoch/nonce/round/phase it refers to.

Membership pruning is a deterministic reducer over committed encounter records,
not a separate reputation state. During epoch advancement, the reducer examines
the verified blocks that will become the new epoch body. If
`RuntimeConfig::consensus_node_removal_policy` is enabled, a subject is removed
from the next epoch's verifier set only when current verifiers provide
supermajority failure evidence for that subject. Stale records, unknown
observers, unknown subjects, self-accusations, duplicate observer records, and
invalid encounter signatures do not count.

The default policy is disabled. `ConsensusNodeRemovalPolicy::supermajority()`
enables the conservative path: supermajority evidence, at most one removal per
epoch, and a configurable minimum retained verifier count. Deployments can
raise the required observer count but cannot lower it below the current
verifier-set supermajority.

### Transaction Validation

After block propagation, the paper expects all non-Byzantine validators
to hold the same preliminary epoch: a deterministic block set, with
transactions ordered inside each block. Default trustless builds enable
`fair-block-ordering`, so the epoch block tree is derived from fair-order
commitments rather than raw block-hash order and ledger-style applications are
not expected to execute blocks by grindable hash position. Each validator then
independently verifies the epoch, applies valid transaction bodies to the
append-only ledger, and signs the resulting epoch hash.

The current crate preserves the protocol-side foundations for that
work:

- block hash and signature verification in `src/block.rs`
- default trustless fair-order block commitments and ordered maps for block
  sets and signature trees
- epoch chain and epoch body containers in `src/state.rs`

Full transaction validation is intentionally not implemented here yet.
The paper's transaction tagging, derivative hash, append-only ledger
state, account/index update rules, and auditing/query behavior should
be implemented as a ledger layer that consumes finalized blocks through
`EpochBody::ordered_blocks()`. Ledger adapters that require fair ordering
should use default trustless builds on every validator; legacy raw ordering is
available only through explicit `--no-default-features` builds.

Filtered transactions preserve that boundary. Blossom validates canonical slot
commitments, tombstone shape, and full-payload hash matches, but the meaning of
`kind`, key hashes, target selection, and delivery policy remains
application-owned.

## Consensus Tree

The paper describes a deterministic consensus tree that lets every node
derive the same quorum schedule from the membership set and an epoch
seed. The implementation keeps this in `src/algorithm.rs`:

- `QUORUM_SIZE` is six.
- `SUPERMAJORITY` is two-thirds.
- `find_round_number` computes the optimal network size and round
  count using base-six growth.
- `select_quorums` sorts the membership set, optionally shuffles it
  deterministically from a hash seed, and returns the quorums relevant
  to the local node.

The shuffle is deterministic and seed-driven so the topology can change
between epochs while remaining independently reproducible by every
validator.

## Overlay Mode

`OverlayRuntime` exposes the transport-facing pieces of Blossom without
creating local epoch state. It owns a node identity plus an address book,
registers multiple consensus services, selects fan-out targets with the
same topology algorithm, and broadcasts `WireRequest` or `Msg` values over
the TCP wire path.

`NodeRuntime` exposes the same broadcast surface for full consensus nodes when
deployers need to send protocol wire requests through the selected topology.
Routine application coordination state should use the block-carried
application-state payload above so it is delivered as part of normal consensus
rather than as an extra message stream.

Overlay mode does not commit blocks, so the block-carried application-state
channel is available only in the consensus runtime.

## Implemented Now

- Primary Blossom message structures.
- Deterministic quorum and round selection.
- Root/subnet consensus groups with group-bound genesis epochs and TCP
  grouped-request routing.
- Direct point-to-point ping/pong liveness requests.
- Overlay runtime and runtime broadcast APIs using the quorum topology.
- Bounded block application-state payloads for piggy-backed coordination.
- Signed encounter records for missing or invalid consensus-phase signatures.
- Opt-in epoch-boundary verifier removal from committed supermajority evidence.
- Primary dispatch, echo, verification, proposal, and commit message
  flow.
- Local consensus, temporary quorum state, and epoch chain structures.
- Dispatch body verification against block hashes, block signatures,
  and signature-tree hashes.
- Trusted block/message paths that skip signatures while preserving
  membership and hash/merkle integrity checks.
- Message matrix behavior for expected quorum messages.
- Address book, local block queue, node status, block intake, dispatch
  generation, and protocol message intake.
- A raw TCP `blossom-node` binary with the initial deployable node
  API.
- A `blossom-harness` binary and TCP end-to-end test suite for simulated
  node behavior.

## Paper-Defined Extensions

The paper also describes behavior that should remain visible in the
architecture, but is not part of this extraction yet:

- The secondary distribution-failure recursion:

  ```text
  Appraisal -> Echo -> Verification -> Proposal -> Request -> Commit
  ```

- Request/response recovery for blocks missing after a failed quorum.
- Restate/reinitialization after failed global finality.
- Additional Byzantine-pruning policy hooks beyond signed participation
  evidence, such as richer application-defined slashing rules.
- Full transaction tagging, derivative epoch hashing, and append-only
  ledger application.
- Durable node discovery, storage, metrics, and production deployment
  manifests.

Those pieces should be added as separate layers or follow-up crates so
the core protocol library remains portable.
