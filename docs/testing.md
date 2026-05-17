# Testing

The test suite is split between focused unit tests and TCP end-to-end
tests that exercise the deployable node path over real local sockets.

## Commands

Run everything:

```sh
cargo test
```

Run only the end-to-end suite:

```sh
cargo test --test e2e_tcp
```

Run the interactive simulation harness:

```sh
cargo run --bin blossom-harness -- --nodes 6 --transactions 3
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

## Harness

`src/harness.rs` provides:

- `SimulatedCluster`: starts N local TCP Blossom nodes with a shared
  genesis verifier set.
- `SimulatedNode`: request helper for a running simulated node.
- `MockBlockService`: TCP service that records nonce updates, serves
  blocks by nonce, and records received blocks.
- `signed_block`: helper for constructing signed blocks against a
  target epoch/nonce.

`src/bin/blossom-harness.rs` uses those pieces to run a compact scenario
that registers a block service, submits a signed block, dispatches it,
and forwards the dispatch to another node.
