# Source Map

This extraction used the current `eden-mdbs` repo as the primary source and
the earlier `eden-poc` repo as a structural reference.

## Current Eden Source

- `consensus_service/src/stc/blossom.rs` -> `src/blossom.rs`
- `consensus_service/src/stc/state.rs` -> `src/state.rs`
- `consensus_service/src/stc/messages.rs` -> `src/messages.rs`
- `consensus_service/src/register.rs` -> `src/register.rs`
- `consensus_service/src/algorithm.rs` -> `src/algorithm.rs`
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

## Extraction Choices

- The new crate keeps protocol data structures and pure state transitions, but drops Actix actors, HTTP connectors, database adapters, metrics, CLI, and deployment files.
- The POC's generic layout informed the module boundary, while the current repo's concrete Ed25519/hash/nonce direction informed the public types.
- The quorum round calculation keeps the original base-6 logic and applies the same floating-point tolerance to the final round count, avoiding an off-by-one at exact powers such as `216`.
- `TempQuorum::verify` now verifies block hashes and Ed25519 signatures directly through the extracted block/crypto primitives.
