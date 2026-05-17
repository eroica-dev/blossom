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
- `src/service_client.rs`: TCP client helpers for block and engine service interactions.
- `src/bin/blossom-node.rs`: raw TCP node process.
- `paper/`: LaTeX protocol paper source and figure assets used as the architecture reference.
- `docs/architecture.md`: paper-informed architecture map for the extracted crate.
- `docs/source-map.md`: source files used for the extraction.

## Run A Node

```sh
cargo run --bin blossom-node -- --host 127.0.0.1 --port 8080
```

The node generates a keypair if `BLOSSOM_PUBLIC_KEY` and
`BLOSSOM_SECRET_KEY` are not provided. For a stable deployment, provide
both values and register external services with `--service` or
`POST /address-book`.

```sh
cargo run --bin blossom-node -- \
  --host 127.0.0.1 \
  --port 8080 \
  --service block:<pubkey>@127.0.0.1:9000
```

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

## Verify

```sh
cargo test
```

## Notes

The original `consensus_service` crate is service-coupled and currently
excluded from the `eden-mdbs` workspace. This extraction keeps the
protocol surface portable while restoring the missing deployment
interfaces needed by a node process.
