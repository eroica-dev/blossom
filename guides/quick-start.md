# Quick Start

Blossom requires Rust 1.93. The repository's `rust-toolchain.toml` selects the
matching compiler, Rustfmt, and Clippy components.

## Test

```sh
cargo test --workspace
```

Run the release gate:

```sh
scripts/release-gate.sh
```

The gate runs formatting, tests, feature checks, clippy, and formal proof
checks. Logs are written under `target/release-gate/`.

## Run A Local Node

```sh
cargo run --bin blossom-node -- --host 127.0.0.1 --port 8080
```

Run with snapshots, durable blocks, and bootstrap peers:

```sh
cargo run --bin blossom-node -- \
  --host 127.0.0.1 \
  --port 8080 \
  --state-snapshot ./var/blossom-node-8080.snapshot.json \
  --block-store ./var/blossom-node-8080.blocks \
  --bootstrap-services ./var/bootstrap-services.json \
  --sync-bootstrap-address-books
```

## Run Local Tools

```sh
cargo run --bin blossom-harness -- --nodes 6 --transactions 3
cargo run -p blossom-observer --bin blossom-observer -- --help
```

Simulation tools run from the
[`deterministic-simulation`](https://github.com/eden-dev-inc/deterministic-simulation)
checkout with `scripts/blossom/run-epoch-chaos.sh`.

## Embed A Protocol Profile

Applications import Blossom directly and select only the profiles they need:

```toml
[dependencies]
blossom = { package = "blossom-consensus", version = "2.1.0", features = [
    "high-availability",
    "active-passive",
    "trusted-checkpoint-dag",
] }
```

- Use the default features for verified Global Blossom.
- Use `RuntimeConfig::trust_mode = TrustMode::Trusted` plus a trusted epoch-log
  path for durable known-member Global Blossom.
- Use `HighAvailabilityRuntime` for an independent 2–7-node active-active HA
  group.
- Use `ActivePassiveRuntime` for native OpenRaft active-passive replication;
  provide the service's authenticated OpenRaft network and application state
  machine implementations.

See [Feature Flags](feature-flags.md), [Direct Active-Active
Integration](active-active-integration.md), and [Small-Cluster High
Availability](high-availability.md) before choosing a production profile.
