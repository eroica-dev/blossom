# Source Map

This extraction used the current `eden-mdbs` repo as the primary source and
the earlier `eden-poc` repo as a structural reference.

## Current Eden Source

- `consensus_service/src/stc/blossom.rs` -> `src/blossom.rs`
- `consensus_service/src/stc/state.rs` -> `src/state.rs`
- `consensus_service/src/stc/epoch.rs` -> `src/state.rs`
- `consensus_service/src/stc/messages.rs` -> `src/messages.rs`
- `consensus_service/src/register.rs` -> `src/register.rs`
- `consensus_service/src/algorithm.rs` -> `src/algorithm.rs`
- `consensus_service/src/stc/block.rs` -> `src/local_block.rs`
- `consensus_service/src/api/transactions.rs` -> `src/runtime.rs` block intake
- `eden_core/node/src/address_book.rs` and `eden_communication/src/address_book.rs` -> `src/address_book.rs`
- `consensus_service/src/api/address_book.rs` -> `src/runtime.rs` and `src/bin/blossom-node.rs` address-book registration
- `consensus_service/src/actors/service.rs` and `eden_communication/src/nonce.rs` -> `src/service_client.rs`
- `consensus_service/src/actors/network.rs` -> `src/runtime.rs` local dispatch and message intake
- `consensus_service/src/main.rs` -> `src/bin/blossom-node.rs`
- `consensus_service/src/stc/node.rs` and `src/stc/node/node_ed25519.rs` -> `src/node.rs` and `src/crypto.rs`
- `eden_core/format/src/hashtype.rs` and `nonce.rs` -> `src/hash.rs` and `src/nonce.rs`
- `eden_core/block/src/lib.rs` -> `src/block.rs`

## Earlier POC Reference

- `eden-dev-inc/eden-poc/eden/src/stc/blossom.rs`
- `eden-dev-inc/eden-poc/eden/src/stc/state.rs`
- `eden-dev-inc/eden-poc/eden/src/stc/messages.rs`
- `eden-dev-inc/eden-poc/eden/src/register.rs`
- `eden-dev-inc/eden-poc/eden/src/algorithm.rs`
- `eden-dev-inc/eden-poc/eden/src/stc/hash.rs`
- `eden-dev-inc/eden-poc/eden/src/stc/node.rs`
- `eden-dev-inc/eden-poc/eden/src/stc/structures.rs`

## Paper Reference

- `/Users/devon/Desktop/blossom/main.tex` -> `paper/main.tex`
- `/Users/devon/Desktop/blossom/ref.bib` -> `paper/ref.bib`
- `/Users/devon/Desktop/blossom/sections/*.tex` -> `paper/sections/*.tex`
- `/Users/devon/Desktop/blossom/figures/*.tex` -> `paper/figures/*.tex`
- `/Users/devon/Desktop/blossom/images/*.png` -> `paper/images/*.png`

The paper source is used as the architecture reference for the protocol
shape: block formation, block propagation, transaction validation, the
deterministic consensus tree, quorum size, supermajority threshold, and
future distribution-failure recovery messages.

## Extraction Choices

- The new crate keeps protocol data structures and pure state transitions, and now restores the address book, local block queue, raw TCP node API, and basic TCP service connectors needed for a deployable node.
- The old DB-backed node registration actor, metrics service, Kubernetes files, and application ledger logic remain outside this extraction.
- The POC's generic layout informed the module boundary, while the current repo's concrete Ed25519/hash/nonce direction informed the public types.
- The paper's protocol section is captured in `docs/architecture.md` as the guiding architecture map for future implementation work.
- Epoch verifier membership uses Eden's `indextreemap::IndexTreeMap` so quorum selection and epoch-signature approval can address validators by deterministic index, matching the original consensus-tree code.
- Epoch block roots use the same `rs_merkle` Merkle root construction from `consensus_service/src/stc/state.rs`.
- The quorum round calculation keeps the original base-6 logic and applies the same floating-point tolerance to the final round count, avoiding an off-by-one at exact powers such as `216`.
- `TempQuorum::verify` now verifies block hashes and Ed25519 signatures directly through the extracted block/crypto primitives.
- `NodeRuntime::submit_block` mirrors Eden's `POST /block` behavior by accepting only signed blocks for the next epoch nonce, rejecting duplicate queued nonces, and enforcing the registered block-service key when present.
- `src/wire.rs` replaces route-based transport with a compact custom protocol: one length-prefixed Borsh `WireRequest` followed by one length-prefixed Borsh `WireResponse`.
- `src/tcp.rs`, `src/harness.rs`, and `tests/e2e_tcp.rs` make the TCP node path reusable by the production binary, the simulation harness, and the end-to-end test suite.
