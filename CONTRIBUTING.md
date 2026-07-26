# Contributing

Thanks for helping improve Blossom.

Use Rust 1.93; `rust-toolchain.toml` pins the required toolchain and components.

Before submitting changes, run:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Protocol changes should include tests for the relevant safety boundary. When a
change affects claims in `docs/proofs/`, update the proof note and any benchmark
or simulation command used to validate it.

Changes to HA, trusted durability, scheduling, recovery, or service directives
must also run the deterministic PR gate:

```sh
./scripts/deterministic-pr-gate.sh
```

Commit only minimized deterministic regressions under
`tests/deterministic/regressions/`. Generated traces, reports, and benchmark
artifacts remain under `target/`.

Keep trusted and trustless behavior separate. Optimizations that change
cryptographic assumptions, payload availability, admission, reconciliation, or
Byzantine fault tolerance need explicit feature flags or runtime validation.
