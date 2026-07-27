# Changelog

All notable changes to Blossom are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Blossom uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html) for its
public Rust APIs and separately versions consensus and durable wire formats.

## [Unreleased]

No changes yet.

## [2.0.0] - 2026-07-27

### Added

- Native global-ordered, trusted active-active, and OpenRaft active-passive
  profiles behind explicit feature and runtime boundaries.
- Opaque application commands and results, bounded `status` and `wait_for`,
  terminal `Applied` completion, and the optional `GlobalApplied` write mode.
- Consensus-certified fresh read barriers for partition-safe linearizable
  reads.
- Certified epoch suffix catch-up with genesis, chain, block, Merkle-root,
  membership-transition, and previous-verifier validation.
- A committed member registry separating `client`, `relay`, and `validator`
  capabilities, with add, revoke, suspend, and key-rotation operations.
- Signed, expiring, generation-monotonic relay records and fail-closed verified
  membership leases with efficient membership subscriptions.
- Active-active learner catch-up, contract-aware cutover, activation,
  accepted-write recertification or abort, recovery status, and signed
  manifests.
- Active-passive learners, joint-consensus membership changes, snapshots,
  linearizable reads, and application-defined state-machine integration.
- Public transactional `BlossomLogStore` storage, backed by the standalone
  `shardlog` crate, for active-active, trusted epochs, HA, OpenRaft, and
  application state.
- Certified HA history compaction and checkpoint-bound reactivation evidence.
- Configurable network deadlines, connection limits, request bounds, signed
  watermarks, and crash-safe durable recovery.

### Changed

- The crates.io package is named `blossom-consensus`; its Rust library name
  remains `blossom`.
- Rust 1.93 is the minimum supported Rust version for every profile.
- `BatchReference` format and codec version 2 commit the route generation and
  application command-spec version.
- Secret signing material is memory-only and excluded from durable identities,
  snapshots, logs, wire messages, and unrestricted formatting.
- Active-passive and active-active durability now share the embedded ShardLog
  backend. Earlier development redb files are an explicit reset or certified
  recovery boundary and are never overwritten.

### Removed

- The closed `BlindWrite`/`Append`/`CompareAndSwap` command model and the
  duplicate internal application state machine.
- `EpochChainRange`; `CertifiedEpochSuffix` is the stronger catch-up contract.
- The global-ordered profile's non-terminal `Sealed`/`Converged` completion
  model.
- Direct Blossom dependencies on `shard-stream-core`,
  `shard-stream-storage`, and redb.

[Unreleased]: https://github.com/d-tietjen/blossom/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/d-tietjen/blossom/releases/tag/v2.0.0
