# blossom

`blossom` is a focused Rust library for the Eden Blossom consensus protocol.
It was extracted from `eden-mdbs/consensus_service` and cross-checked against
the earlier `eden-dev-inc/eden-poc` implementation.

The repo intentionally contains only protocol logic:

- Blossom message types: dispatch, echo response/request, verification, proposal, commit, and epoch started.
- Quorum and round selection.
- Consensus state, temporary quorum state, proposal/verification counting, and epoch advancement.
- Minimal cryptographic and block primitives needed for the protocol to compile independently.
- Unit tests for signing, block verification, quorum selection, message matrix behavior, and quorum state reuse.

It does not include the old Actix actors, HTTP APIs, database adapters, metrics service, Kubernetes files, or application-specific ledger logic.

## Layout

- `src/blossom.rs`: protocol message structs, body hashing/signing, signature tree, dispatch verification helpers.
- `src/state.rs`: local state, epoch chain, temporary consensus/quorum state, proposal and verification counts.
- `src/register.rs`: Blossom message matrix and quorum queue.
- `src/algorithm.rs`: deterministic quorum/round selection.
- `src/crypto.rs`: Ed25519 public keys, secret keys, signatures, and key generation.
- `src/block.rs`: minimal signed block and transaction envelope used by dispatch verification.
- `docs/source-map.md`: source files used for the extraction.

## Verify

```sh
cargo test
```

## Notes

The original `consensus_service` crate is service-coupled and currently excluded from the `eden-mdbs` workspace. This extraction removes that coupling and keeps the protocol surface library-shaped, so future service implementations can build on it without pulling in HTTP, database, or actor runtime concerns.
