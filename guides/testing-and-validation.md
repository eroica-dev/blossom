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
- `verification/run-formal.sh`

## Production Validation

```sh
scripts/production-validation.sh
```

This runs the broader protocol validation matrix, including TCP finality,
Byzantine reconnect simulation, 100 ms latency simulation, and proof validation
workloads.

## Benchmarks

Benchmark and simulation entry points live under `benchmarks/scripts/`.

Useful starting points:

```sh
benchmarks/scripts/run-epoch-chaos.sh
benchmarks/scripts/run-prefill-head-to-head.sh
benchmarks/scripts/run-proof-validation-matrix.sh
```
