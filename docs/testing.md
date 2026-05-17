# Testing

The test suite is split between focused unit tests and TCP end-to-end
tests that exercise the deployable node path over real local sockets.

## Commands

Run everything:

```sh
cargo test
```

Run the opt-in non-cryptographic hash build:

```sh
cargo test --features insecure-fast-hash
```

That feature is for trusted/performance experiments. The default test run is
the secure SHA-256 protocol path.

Run only the end-to-end suite:

```sh
cargo test --test e2e_tcp
```

Run the interactive simulation harness:

```sh
cargo run --bin blossom-harness -- --nodes 6 --transactions 3
```

Run benchmark smoke checks:

```sh
cargo bench --bench protocol -- --test
cargo run --release --bin blossom-harness-bench -- \
  --nodes 2 --transactions 1 --iterations 1 --warmup 0
```

## End-To-End Coverage

`tests/e2e_tcp.rs` covers:

- TCP framing with `WireRequest` and `WireResponse`.
- Node health, state, address-book, and next-nonce requests.
- Address-book registration and block-service nonce announcement.
- TCP service-client behavior against a mock block service:
  `SendNonce`, `BlockNonce`, `GetBlock`, and `SendBlock`.
- Signed block submission, duplicate block rejection, invalid nonce
  rejection, `SendBlock`, and local dispatch generation.
- Protocol message intake for every current `Msg` variant:
  `Dispatch`, `EchoResponse`, `EchoRequest`, `EchoReDispatch`,
  `Verification`, `Proposal`, `Commit`, `EpochStarted`, `Ok`, and
  `Fail`.
- Overlay broadcast over the topology fan-out API using local TCP nodes.
- Trusted-cluster intake where unsigned blocks and default-signature
  dispatches are accepted from known members and still rejected from
  unknown senders.

## Unit Coverage

The library unit tests cover expected behavior and failure behavior for:

- hashing, hex/JSON conversion, nonce arithmetic, and ordered map
  hashing
- Ed25519 key/signature parsing, serialization, signing, and rejection
  paths
- node identity signing and secret-key serialization hygiene
- service-kind parsing, multi-peer address-book registration/removal, and endpoint
  formatting
- transaction hashing, block signing, block integrity, and tamper
  detection
- deterministic quorum selection, shuffling, supermajority thresholds,
  message matrices, and quorum queues
- signature trees, dispatch body verification, message enum conversion,
  and Blossom body signatures
- local block queue capacity, duplicate nonce rejection, stale/future
  nonce behavior, and validator checks
- epoch advancement, verification/proposal counting, epoch approval, and
  Merkle-rooted block sets
- runtime status, block-service key enforcement, empty dispatches, and
  message rejection paths
- overlay fan-out target selection and direct/topology target filtering
- trusted runtime behavior for unsigned block submission, unsigned
  dispatch intake, known-member enforcement, trusted dispatch-body
  verification, and trusted quorum verification
- frame-size rejection, TCP request dispatch, and harness helper behavior

## Harness

`src/harness.rs` provides:

- `SimulatedCluster`: starts N local TCP Blossom nodes with a shared
  genesis verifier set. Use `spawn_trusted` or `spawn_with_trust_mode`
  to exercise the trusted known-member fast path.
- `SimulatedNode`: request helper for a running simulated node.
- `MockBlockService`: TCP service that records nonce updates, serves
  blocks by nonce, and records received blocks.
- `signed_block`: helper for constructing signed blocks against a
  target epoch/nonce.

`src/bin/blossom-harness.rs` uses those pieces to run a compact scenario
that registers a block service, submits a signed block, dispatches it,
and forwards the dispatch to another node.
