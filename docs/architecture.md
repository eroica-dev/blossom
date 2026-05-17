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

- `src/block.rs`: signed block and transaction envelope primitives.
- `src/local_block.rs`: queued block intake from the block service and
  locally closed blocks.
- `src/address_book.rs`: service registry for block, engine, relay,
  consensus, and address-book services.
- `src/runtime.rs`: next-nonce checks and signed block acceptance.
- `src/crypto.rs`: Ed25519 signing and verification.
- `src/hash.rs` and `src/nonce.rs`: deterministic identifiers used by
  blocks, epochs, and messages.

The extraction intentionally keeps transaction semantics minimal.
Application transaction schemas, ledger adapters, block size policy, and
mempool behavior belong above this crate or in a follow-up ledger layer.

### Block Propagation

The paper's consensus protocol is centered on block propagation through
deterministic quorums. The canonical quorum size is six nodes, with a
two-thirds supermajority threshold. Non-consensus traffic remains normal
peer-to-peer communication, while consensus traffic uses a structured
quorum topology derived independently by every node.

The current implementation maps that layer to:

- `src/algorithm.rs`: deterministic quorum and round selection.
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

Trusted mode is an explicit private-cluster optimization. When
`RuntimeConfig::trust_mode` is `Trusted`, nodes assume the verifier set
was provisioned out of band and skip Ed25519 block/message signing and
verification. The runtime still checks that message senders belong to the
current round and that blocks match their content hash and Merkle root.
The epoch-depth benchmark uses this mode to model dispatch-only quorum
propagation, removing echo, verification, proposal, and commit messages
from the known-member fast path.

### Transaction Validation

After block propagation, the paper expects all non-Byzantine validators
to hold the same preliminary epoch: a deterministically ordered block
set, with transactions ordered inside each block. Each validator then
independently verifies the epoch, applies valid transaction bodies to
the append-only ledger, and signs the resulting epoch hash.

The current crate preserves the protocol-side foundations for that
work:

- block hash and signature verification in `src/block.rs`
- ordered maps for block sets and signature trees
- epoch chain and epoch body containers in `src/state.rs`

Full transaction validation is intentionally not implemented here yet.
The paper's transaction tagging, derivative hash, append-only ledger
state, account/index update rules, and auditing/query behavior should
be implemented as a ledger layer that consumes this crate's finalized
block sets.

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

## Implemented Now

- Primary Blossom message structures.
- Deterministic quorum and round selection.
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
- Byzantine pruning policy.
- Full transaction tagging, derivative epoch hashing, and append-only
  ledger application.
- Durable node discovery, storage, metrics, and production deployment
  manifests.

Those pieces should be added as separate layers or follow-up crates so
the core protocol library remains portable.
