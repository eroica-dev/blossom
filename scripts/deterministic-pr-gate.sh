#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${DETERMINISTIC_OUT_DIR:-"$ROOT/target/deterministic-sandbox/pr"}"
mkdir -p "$OUT_DIR"

run_step() {
  local name="$1"
  shift
  printf '==> %s\n' "$name"
  (
    cd "$ROOT"
    "$@"
  ) >"$OUT_DIR/$name.log" 2>&1
  printf 'ok: %s\n' "$name"
}

run_step fmt cargo fmt --all -- --check
run_step deterministic-kernel cargo test -p deterministic-test-env
run_step deterministic-adapters \
  cargo test -p blossom-sim --features high-availability deterministic::tests
run_step product-owned-adapter \
  cargo test -p blossom-sim --features parallel-networks \
  --bin blossom-deterministic-adapter
run_step ha-application-correctness \
  cargo test -p blossom-bench-harness ha_adapter::tests
run_step independent-history-checker \
  cargo test -p blossom-bench-harness correctness::tests
run_step observability-adapters \
  cargo test -p blossom --no-default-features \
  --features observability,high-availability \
  telemetry::tests -- \
  --skip telemetry::tests::jsonl_tcp_sink_batches_and_flushes_on_drop
run_step all-hegel \
  cargo test -p blossom --all-features \
  --test hegel_active_active \
  --test hegel_high_availability \
  --test hegel_parallel_networks \
  --test hegel_quorum \
  --test hegel_trusted_dag \
  --test hegel_trusted_network
run_step verified-default-regression cargo test -p blossom --no-default-features
run_step parallel-network-regression \
  cargo test -p blossom --features parallel-networks parallel_networks::tests
run_step openraft-durable-restart \
  cargo test -p blossom-bench-harness \
  raft_adapter::tests::durable_cluster_kill_restart_and_catch_up_is_a_real_restart
run_step openraft-deterministic-control \
  cargo run --release -p blossom-bench-harness \
  --bin blossom-raft-deterministic -- \
  --commands 50 \
  --output "$OUT_DIR/openraft-report.json"
run_step deterministic-pr-campaign \
  cargo run --release -p blossom-sim --features parallel-networks,observability \
  --bin blossom-deterministic-campaign -- \
  --profile pr \
  --output "$OUT_DIR/report.json" \
  --metrics-output "$OUT_DIR/metrics.prom"

printf 'deterministic PR artifacts: %s\n' "$OUT_DIR"
