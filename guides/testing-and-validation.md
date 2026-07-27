# Testing And Validation

## Release Gate

```sh
scripts/release-gate.sh
```

The release gate runs:

- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo test --workspace --all-features`
- `cargo test -p blossom-consensus --no-default-features`
- standalone `active-passive` compile check
- `cargo test -p blossom-consensus --features insecure-fast-hash`
- standalone `telemetry`, `eden-logger`, and combined
  `observability,high-availability,trusted-checkpoint-dag` compile checks
- `cargo clippy --workspace --all-features --all-targets -- -D warnings`
- `scripts/active-passive-production-validation.sh`
- `scripts/trusted-production-validation.sh`
- `scripts/ha-production-validation.sh`
- `verification/run-formal.sh`

The GitHub Actions workflow `HA Merge Gate` runs this complete command on every
pull request and push to `main`. Repository branch protection must require its
`Release and HA production gate` job.

Authoritative Blossom simulation gates run in
[`eden-dev-inc/deterministic-simulation`](https://github.com/eden-dev-inc/deterministic-simulation)
against a full pinned Blossom revision. That repository owns the adapter,
profiles, fault campaigns, VM specifications, and regression corpus.

## Production Validation

```sh
scripts/production-validation.sh
```

This runs the broader non-simulation protocol validation matrix, including TCP
finality and proof-validation throughput workloads.

The trusted-network gate includes immediate-durability ENOSPC/fsync fault
injection, crash/restart recovery, quorum-intersection and dispatch-mask
properties, and atomic multi-reference finalization. It also verifies that
parallel HA/Global Blossom coordination never merges memberships or quorum
votes:

```sh
scripts/trusted-production-validation.sh
```

The focused HA gate also includes 1,001+ epoch durability tests, authenticated
subprocess kill/restart, ENOSPC and fsync atomicity, and Hegel properties:

```sh
scripts/ha-production-validation.sh
```

The active-passive gate runs the native OpenRaft election, contract-fence,
learner, joint-consensus replacement, failover, and read-barrier integration
test. It also performs 1,001 opaque writes while repeatedly killing and
restarting leaders and followers against the shipped ShardLog-backed log:

```sh
scripts/active-passive-production-validation.sh
```

## Benchmarks

Product benchmark entry points live under `benchmarks/scripts/`.

Useful starting points:

```sh
benchmarks/scripts/run-prefill-head-to-head.sh
benchmarks/scripts/run-proof-validation-matrix.sh
```
# Deterministic protocol exploration

The simulation repository owns `blossom-sim`, the protocol-v1 process adapter,
PR/nightly/release profiles, deterministic fault and recovery models, VM tiers,
and minimized regression scenarios. See
[Deterministic Verification Sandbox](deterministic-sandbox.md) for the
ownership boundary and canonical commands.
