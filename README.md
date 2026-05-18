# blossom

`blossom` is a focused Rust library and node binary for the Eden Blossom
consensus protocol. It was extracted from `eden-mdbs/consensus_service`
and cross-checked against the earlier `eden-dev-inc/eden-poc`
implementation.

The repo contains the reusable protocol layer plus the first deployable
node surface:

- Blossom message types: dispatch, echo response/request, verification, proposal, commit, and epoch started.
- Quorum and round selection.
- Consensus state, temporary quorum state, proposal/verification counting, and epoch advancement.
- Indexed verifier membership, epoch approval checks, and Merkle-rooted epoch block sets.
- Parallel consensus groups for a root network plus narrower-purpose
  subnets with separate membership, epoch chains, and block/application
  data.
- Bounded opaque application state in each block header for piggy-backed
  coordination signals.
- Address book and service registration for block, engine, consensus, relay, and address-book services.
- Overlay runtime APIs for address-book-backed fan-out without starting
  the epoch state machine.
- Local block intake/queueing for signed block-service output.
- Optional trusted-cluster mode for private known-member deployments that
  skip block/message signatures while retaining membership and hash/merkle
  integrity checks.
- Optional `filtered-transactions` build feature for committing a canonical
  transaction slot to every validator while allowing non-target nodes to keep
  only a tombstone and payload commitment.
- Optional `availability-gossip` build feature for disseminating filtered
  payload availability and serving target-authorized payload fetches.
- Optional `insecure-fast-hash` build feature for trusted/performance
  experiments that swaps protocol SHA-256 commitments for XXH3.
- A raw TCP `blossom-node` binary with a length-prefixed Borsh wire protocol for health, state, address book, block intake, dispatch, and message handling.
- Reusable encoded wire frames for cached broadcast/fan-out sends.
- Minimal cryptographic and block primitives needed for the protocol to compile independently.
- Unit tests for signing, block verification, quorum selection, address-book behavior, block queueing, message matrix behavior, and runtime block dispatch.

It does not yet include Eden's old database adapters, metrics service,
Kubernetes files, or application-specific ledger logic. The TCP node
runtime is intentionally smaller than the original actor stack, but keeps
the deploy-time interfaces needed to start wiring nodes and external
block/engine services together.

## Layout

- `src/blossom.rs`: protocol message structs, body hashing/signing, signature tree, dispatch verification helpers.
- `src/state.rs`: local state, epoch chain, indexed verifier membership, epoch approval, temporary consensus/quorum state, proposal and verification counts.
- `src/register.rs`: Blossom message matrix and quorum queue.
- `src/algorithm.rs`: deterministic quorum/round selection.
- `src/group.rs`: stable root/subnet consensus group identifiers.
- `src/availability.rs`: filtered payload availability gossip, fetch, and
  dissemination estimates.
- `src/crypto.rs`: Ed25519 public keys, secret keys, signatures, and key generation.
- `src/block.rs`: signed block, opaque transaction payloads, optional
  filtered transaction slots, and bounded opaque application-state payload
  used by dispatch verification.
- `src/address_book.rs`: service registry copied from the Eden runtime shape.
- `src/local_block.rs`: local signed block queue and build-block helper.
- `src/overlay.rs`: overlay runtime, fan-out strategies, and broadcast reports.
- `src/runtime.rs`: deployable node runtime over local state, address book, and block intake.
- `src/wire.rs`: length-prefixed Borsh request/response protocol.
- `src/tcp.rs`: reusable TCP node server and request client.
- `src/service_client.rs`: TCP client helpers for block and engine service interactions.
- `src/harness.rs`: in-process simulation cluster and mock block service.
- `src/bin/blossom-node.rs`: raw TCP node process.
- `src/bin/blossom-harness.rs`: local node-behavior simulation runner.
- `src/bin/blossom-harness-bench.rs`: CSV-emitting full harness benchmark driver.
- `tests/e2e_tcp.rs`: TCP end-to-end coverage for node and service behavior.
- `benches/protocol.rs`: Criterion microbenchmarks for protocol primitives and runtime paths.
- `benchmarks/`: shell-script benchmark runners and ignored CSV result directory.
- `paper/`: LaTeX protocol paper source and figure assets used as the architecture reference.
- `docs/architecture.md`: paper-informed architecture map for the extracted crate.
- `docs/source-map.md`: source files used for the extraction.
- `docs/testing.md`: end-to-end testing and harness guide.

## Run A Node

```sh
cargo run --bin blossom-node -- --host 127.0.0.1 --port 8080
```

The node generates a keypair if `BLOSSOM_PUBLIC_KEY` and
`BLOSSOM_SECRET_KEY` are not provided. For a stable deployment, provide
both values and register external services with `--service` or
`WireRequest::RegisterService`.

```sh
cargo run --bin blossom-node -- \
  --host 127.0.0.1 \
  --port 8080 \
  --service block:<pubkey>@127.0.0.1:9000
```

For a private cluster where all validators are provisioned from the same
trusted membership set, `--trusted` or `BLOSSOM_TRUSTED=true` disables
Ed25519 block/message signing and verification. This is a raw-speed mode
for controlled deployments; nodes still reject unknown senders and invalid
block hashes or Merkle roots.

For benchmarking the non-cryptographic lower bound, build with
`--features insecure-fast-hash`. This replaces protocol SHA-256 hashing with
XXH3 while keeping the same `HashType` wire shape. It is not the default and
should not be used for the verified protocol unless the deployment explicitly
accepts non-cryptographic commitments.

Wire requests:

- `Health`
- `Ping(NodePing)`
- `State`
- `AddressBook`
- `RegisterService(Service)`
- `Group { group_id, request }`
- `NextNonce`
- `SubmitBlock(Block)`
- `Dispatch { round }`
- `Message(Msg)`
- `SendNonce(Nonce)`
- `BlockNonce(Nonce)`
- `GetBlock(Nonce)`
- `SendBlock(Block)`

Each connection carries one frame:

```text
u32 big-endian payload length
Borsh-encoded WireRequest
```

The response uses the same framing with `WireResponse`.

## Ping A Peer Directly

For point-to-point liveness, send `WireRequest::Ping(NodePing)` directly to
the peer's consensus service. This returns `WireResponse::Pong(NodePong)`
without entering consensus, advancing an epoch, dispatching a block, or
broadcasting to a quorum. The nonce and payload are echoed so callers can
verify the round trip.

```rust
use blossom::{NodePing, TcpServiceClient};

let client = TcpServiceClient::new();
let pong = client
    .ping(&peer_consensus_service, NodePing::with_payload(42, b"hello"))
    .await?;

assert_eq!(pong.nonce, 42);
assert_eq!(pong.payload, b"hello");
```

## Use As An Overlay

`OverlayRuntime` exposes the address book and topology-aware messaging
without instantiating consensus or epoch state. This is useful for DHT,
gossip, and application-level overlay traffic that wants Blossom's
structured fan-out but not block commitment.

```rust
use blossom::{FanOutStrategy, HashType, Msg, OverlayRuntime};

let overlay = OverlayRuntime::new(self_node);
overlay.register_service(peer_consensus_service);

let report = overlay
    .broadcast(Msg::Ok, FanOutStrategy::topology(HashType::hash(b"round")))
    .await?;
```

`NodeRuntime` exposes the same `broadcast` and `broadcast_request` APIs
for deployers that want consensus nodes to send application-level
messages through the selected topology. The address book supports
multiple services per kind, so each consensus peer can be registered
independently.

## Use Consensus Subnets

Blossom can host a root consensus group for the full network and one or
more narrower subnets for purpose-specific data sharing. A subnet has its
own `ConsensusGroupId`, verifier membership, epoch chain, local block
queue, and block-carried application state. The group id is committed into
the genesis epoch hash, so blocks and signed protocol messages from one
group cannot be replayed into another group with a different id.

```rust
use blossom::{
    ConsensusGroupId, MultiGroupRuntime, NodeRuntime, RuntimeConfig,
    WireRequest, genesis_epoch, genesis_epoch_for_group,
};

let root_genesis = genesis_epoch(all_nodes.clone());
let subnet_id = ConsensusGroupId::named("cache-hotset-a");
let subnet_genesis = genesis_epoch_for_group(subnet_id, cache_nodes.clone());

let mut root_config = RuntimeConfig::new(self_node.clone());
root_config.genesis = Some(root_genesis);
let root = NodeRuntime::new(root_config);

let mut subnet_config = RuntimeConfig::for_group(self_node, subnet_id);
subnet_config.genesis = Some(subnet_genesis);
let subnet = NodeRuntime::new(subnet_config);

let multi = MultiGroupRuntime::with_groups(root, [subnet]);
let subnet_request = WireRequest::Group {
    group_id: subnet_id,
    request: Box::new(WireRequest::NextNonce),
};
```

Ungrouped TCP requests are routed to the root group. Grouped requests are
routed to the matching subnet, which lets a single node process participate
in multiple parallel consensus planes while keeping each plane's block data
and application-state payloads separate.

## Opaque Transaction Payloads

Transactions carry application-defined payload bytes. Blossom does not parse
or validate those bytes; it commits the transaction identifier and payload into
the block hash, and uses the transaction identifiers for the block Merkle root.
Applications can use raw bytes or plug in a domain codec above Blossom. For
example, a database, blockchain, or cache module can define its own versioned
operation format and pass the encoded bytes to `Transaction::new`.

Generic Borsh helpers are available for lower-volume or schema-heavy
applications:

```rust
use borsh::{BorshDeserialize, BorshSerialize};
use blossom::Transaction;

#[derive(BorshSerialize, BorshDeserialize)]
struct CachePut {
    version: u16,
    key: Vec<u8>,
    value: Vec<u8>,
}

let tx = Transaction::from_borsh(&CachePut {
    version: 1,
    key: b"session:42".to_vec(),
    value: b"cached-value".to_vec(),
})?;

let decoded: CachePut = tx.payload_as_borsh()?;
```

For high-volume paths, define a purpose-built module codec and store its output
in `TransactionPayload`. For trusted deployments where the application already
has a stable key or content hash, the `external-transaction-hashes` feature lets
callers provide that identifier while still committing the payload bytes into
the block hash.

## Filtered Transactions

The optional `filtered-transactions` feature supports selective payload
materialization without changing the consensus shape. Every validator commits
the same filtered transaction slot: key hash, application kind, sorted target
set, payload commitment, payload length, and delivery policy. Target nodes can
store the full payload locally; non-target nodes store a tombstone. Both views
produce the same transaction id, Merkle root, and block hash.

```rust
use blossom::{FilteredDeliveryPolicy, HashType, Transaction};

let full = Transaction::filtered_full(
    HashType::hash(b"session:42"),
    1,
    vec![target_node],
    b"cached-value".to_vec(),
    FilteredDeliveryPolicy::Gossip,
)?;

let slot = full.filtered_slot().unwrap().clone();
let tombstone = Transaction::filtered_tombstone(slot)?;

assert_eq!(full.hash, tombstone.hash);
assert_eq!(full.to_bytes(), tombstone.to_bytes());
```

This is intentionally named filtered rather than private. The first layer
commits routing metadata and payload hashes; it does not hide metadata or
provide encryption by itself. The `availability-gossip` feature flag is reserved
for the follow-on data-availability layer that can advertise and fetch payload
bytes without forcing all nodes to receive every payload.

With `availability-gossip` enabled, nodes can gossip signed availability
entries for filtered payloads they hold. Targets then fetch payload bytes from a
holder and verify the bytes against the committed payload hash. This keeps the
large data movement out of consensus while avoiding all-to-all payload
broadcast.

For KVCache-style deployments, keys and payload commitments are usually stable
for many epochs. That makes gossip a good fit: availability metadata can be
cached, re-gossiped at a low interval, and refreshed only when holders or
commitments change.

Dissemination time is measured in gossip rounds:

```text
ideal_rounds = ceil(log_(fanout + 1)(node_count))
ideal_delay  = ideal_rounds * gossip_interval
```

The helper `ideal_push_gossip_rounds(node_count, fanout)` exposes this planning
estimate. It assumes each informed node reaches `fanout` new peers per round,
so real deployments should budget at least one extra round for overlap,
scheduler jitter, and packet loss. For 36 nodes with fanout 6, the ideal is 2
rounds. At a 100 ms gossip interval, that is about 200 ms ideal dissemination,
or roughly 300 ms with one safety round.

That estimate is for availability metadata. Time until a target has usable
payload bytes is:

```text
metadata_gossip_delay + fetch_rtt + payload_transfer_time + verification_time
```

## Piggy-Back Application State

Blocks can carry a bounded opaque application-state payload alongside the
validator, epoch, nonce, timestamps, and Merkle root. Blossom commits to
the bytes in the block hash and signature, but does not parse them.
Applications should put their own version tag at the start of the payload
and apply their own compatibility rules.

```rust
use blossom::{BLOCK_APPLICATION_STATE_MAX_BYTES, Block};

let mut block = Block::default();
block.set_application_state(b"v1:bytes_used=1048576;budget=4194304")?;
assert!(block.application_state_len() <= BLOCK_APPLICATION_STATE_MAX_BYTES);
```

The soft budget is 4 KiB and the hard consensus-enforced limit is 8 KiB
per block. Oversized payloads are rejected by block integrity checks.
Under full consensus, committed blocks give every node the same
application-state snapshots in the same epoch order. Overlay-only mode does
not commit blocks, so this ordered piggy-backed state channel is a consensus
runtime feature.

## Run The Harness

```sh
cargo run --bin blossom-harness -- --nodes 6 --transactions 3
```

The harness starts local TCP nodes, starts a mock block service, registers
that service with node 0, submits a signed block, dispatches it, and
delivers the dispatch to another simulated node.

## Verify

```sh
cargo test
```

For only the TCP end-to-end suite:

```sh
cargo test --test e2e_tcp
```

## Benchmark

Run Criterion microbenchmarks:

```sh
./benchmarks/scripts/run-criterion.sh
```

Run a full simulated-node harness benchmark:

```sh
ITERATIONS=10 NODES=6 TRANSACTIONS=3 ./benchmarks/scripts/run-harness.sh
```

Run a harness matrix:

```sh
NODE_COUNTS="1 6 12" TRANSACTION_COUNTS="0 3 32" ITERATIONS=5 \
  ./benchmarks/scripts/run-harness-matrix.sh
```

Run the paper-aligned epoch-depth model in trusted mode:

```sh
cargo run --release --bin blossom-epoch-bench -- \
  --nodes 36 --target-transactions 1000000 \
  --transactions-per-node 1000 --trusted
```

Run the same model with the opt-in non-cryptographic hash path:

```sh
cargo run --release --features insecure-fast-hash --bin blossom-epoch-bench -- \
  --nodes 36 --target-transactions 1000000 \
  --transactions-per-node 1000 --trusted
```

## Notes

The original `consensus_service` crate is service-coupled and currently
excluded from the `eden-mdbs` workspace. This extraction keeps the
protocol surface portable while restoring the missing deployment
interfaces needed by a node process.
