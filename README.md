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
- Address book and service registration for block, engine, consensus, relay, and address-book services.
- Local block intake/queueing for signed block-service output.
- Optional trusted-cluster mode for private known-member deployments that
  skip block/message signatures while retaining membership and hash/merkle
  integrity checks.
- Optional `insecure-fast-hash` build feature for trusted/performance
  experiments that swaps protocol SHA-256 commitments for XXH3.
- A raw TCP `blossom-node` binary with a length-prefixed Borsh wire protocol for health, state, address book, block intake, dispatch, and message handling.
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
- `src/crypto.rs`: Ed25519 public keys, secret keys, signatures, and key generation.
- `src/block.rs`: minimal signed block and transaction envelope used by dispatch verification.
- `src/address_book.rs`: service registry copied from the Eden runtime shape.
- `src/local_block.rs`: local signed block queue and build-block helper.
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
- `State`
- `AddressBook`
- `RegisterService(Service)`
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
