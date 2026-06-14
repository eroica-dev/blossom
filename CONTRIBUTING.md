# Contributing

Thanks for helping improve Blossom.

Before submitting changes, run:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Protocol changes should include tests for the relevant safety boundary. When a
change affects claims in `docs/proofs/`, update the proof note and any benchmark
or simulation command used to validate it.

Keep trusted and trustless behavior separate. Optimizations that change
cryptographic assumptions, payload availability, admission, reconciliation, or
Byzantine fault tolerance need explicit feature flags or runtime validation.
