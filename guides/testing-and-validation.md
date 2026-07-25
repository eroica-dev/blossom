# Testing And Validation

## Release Gate

```sh
scripts/release-gate.sh
```

The release gate runs:

- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo test --workspace --all-features`
- `cargo test -p blossom --no-default-features`
- `cargo test -p blossom --features insecure-fast-hash`
- `cargo clippy --workspace --all-features --all-targets -- -D warnings`
- `scripts/ha-production-validation.sh`
- `verification/run-formal.sh`

The GitHub Actions workflow `HA Merge Gate` runs this complete command on every
pull request and push to `main`. Repository branch protection must require its
`Release and HA production gate` job.

## Production Validation

```sh
scripts/production-validation.sh
```

This runs the broader protocol validation matrix, including TCP finality,
Byzantine reconnect simulation, 100 ms latency simulation, and proof validation
workloads.

The focused HA gate also includes 1,001+ epoch durability tests, authenticated
subprocess kill/restart, ENOSPC and fsync atomicity, Hegel properties, OpenRaft
restart controls, and deterministic 2–7 node fault campaigns:

```sh
scripts/ha-production-validation.sh
```

## Benchmarks

Benchmark and simulation entry points live under `benchmarks/scripts/`.

Useful starting points:

```sh
benchmarks/scripts/run-epoch-chaos.sh
benchmarks/scripts/run-prefill-head-to-head.sh
benchmarks/scripts/run-proof-validation-matrix.sh
```
