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
- `scripts/trusted-production-validation.sh`
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

The trusted-network gate includes immediate-durability ENOSPC/fsync fault
injection, crash/restart recovery, quorum-intersection and dispatch-mask
properties, atomic multi-reference finalization, and a 1,001-epoch trusted
delay/drop/partition/reconciliation campaign. It also verifies that parallel
HA/Global Blossom coordination never merges memberships or quorum votes:

```sh
scripts/trusted-production-validation.sh
```

The focused HA gate also includes 1,001+ epoch durability tests, authenticated
subprocess kill/restart, ENOSPC and fsync atomicity, Hegel properties, and
deterministic 2–7 node fault campaigns:

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
# Deterministic protocol exploration

`deterministic-test-env` provides a protocol-agnostic, discrete-event scheduler
with virtual microsecond time, stable choice identities, exact replay,
directed-link faults, process and storage faults, client `Unknown` outcomes,
global property aggregation, partial-order reduction, and trace minimization.
The existing `HermeticPlan` API remains available as a compatibility wrapper.

Run the merge-sized gate with:

```sh
./scripts/deterministic-pr-gate.sh
```

Run the nightly-grade campaign with:

```sh
./scripts/deterministic-campaign.sh --profile nightly --budget 2h
```

Campaign artifacts are written below `target/deterministic-sandbox/`. Each HA
cell includes its scenario, compact event/state-digest stream, client history,
property report, fault coverage, and replay manifest. Full traces are retained
for failures, along with their minimized regression. Generated traces are not
committed; only minimized regression scenarios belong in source control.

The HA adapter drives the real `HighAvailabilityRuntime` one dispatch,
acknowledgement, confirmation, fault, and recovery event at a time. Trusted
global Blossom continues through the existing epoch simulator with long
partitioned runs. Parallel-network cells cover every 2–7-node HA group against
6- and 12-node Global Blossom networks and verify that one network's outage
does not cross-advance or stop the other. OpenRaft remains a harness-only
active-passive control, covers every 2–7-node physical footprint, and is not
linked into Blossom core.
