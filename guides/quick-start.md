# Quick Start

## Test

```sh
cargo test --workspace
```

Run the pre-release gate:

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
benchmarks/scripts/run-epoch-chaos.sh
```
