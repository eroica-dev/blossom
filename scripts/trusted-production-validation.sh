#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-"$ROOT/target/trusted-production-validation"}"
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

run_step trusted-durable-log \
  cargo test -p blossom --lib trusted_log::tests -- --nocapture

run_step trusted-runtime \
  cargo test -p blossom --lib runtime::tests::trusted_ -- --nocapture

run_step trusted-runtime-durable-restart \
  cargo test -p blossom --lib runtime::tests::durable_trusted -- --nocapture

run_step trusted-reference-atomicity \
  cargo test -p blossom --lib \
  active_active::tests::trusted_epoch_finalizes_all_writer_references_in_btree_block_order \
  -- --nocapture

run_step trusted-hegel-properties \
  cargo test -p blossom --test hegel_trusted_network -- --nocapture

run_step trusted-checkpoint-dag-properties \
  cargo test -p blossom --features trusted-checkpoint-dag \
  trusted_dag::tests -- --nocapture

run_step trusted-checkpoint-dag-hegel \
  cargo test -p blossom --features trusted-checkpoint-dag \
  --test hegel_trusted_dag -- --nocapture

run_step parallel-ha-global-coordination \
  cargo test -p blossom --features parallel-networks \
  parallel_networks::tests -- --nocapture

run_step parallel-ha-global-hegel \
  cargo test -p blossom --features parallel-networks \
  --test hegel_parallel_networks -- --nocapture

run_step trusted-tcp \
  cargo test -p blossom --test e2e_tcp trusted_cluster_accepts_unsigned_block_and_dispatch \
  -- --nocapture

run_step trusted-hierarchical-tcp \
  cargo test -p blossom-bench-harness --lib \
  blossom_adapter::tests::trusted_tcp_cluster_orders_all_parallel_writer_blocks_by_hash \
  -- --nocapture

run_step trusted-1001-epoch-chaos \
  cargo run --release -p blossom-sim --bin blossom-sim-epoch-chaos -- \
  --nodes 12 \
  --epochs 1001 \
  --transactions-per-node 1 \
  --transaction-bytes 16 \
  --latency-ms 5 \
  --jitter-ms 10 \
  --drop-ppm 5000 \
  --spike-ppm 10000 \
  --spike-latency-ms 75 \
  --repair-rounds 4 \
  --repair-fanout 9 \
  --repair-quorum 8 \
  --partition-start-epoch 400 \
  --partition-end-epoch 460 \
  --partition-left-nodes 4 \
  --trusted \
  --shuffle \
  --require-reconciliation \
  --seed 8391163481963729733

printf 'trusted production validation logs: %s\n' "$OUT_DIR"
