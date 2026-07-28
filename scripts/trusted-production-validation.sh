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
  cargo test -p blossom-consensus --lib trusted_log::tests -- --nocapture

run_step trusted-runtime \
  cargo test -p blossom-consensus --lib runtime::tests::trusted_ -- --nocapture

run_step trusted-runtime-durable-restart \
  cargo test -p blossom-consensus --lib runtime::tests::durable_trusted -- --nocapture

run_step trusted-reference-atomicity \
  cargo test -p blossom-consensus --lib \
  active_active::tests::trusted_epoch_finalizes_all_writer_references_in_btree_block_order \
  -- --nocapture

run_step active-active-store-identity-and-normalized-restart \
  cargo test -p blossom-consensus --lib \
  active_active::tests::durable_store_ \
  -- --nocapture

run_step active-active-q3-q6-q9 \
  cargo test -p blossom-bench-harness --lib \
  blossom_adapter::tests::active_active_q3_q6_q9_paths_finalize_and_apply \
  -- --nocapture

run_step trusted-hegel-properties \
  cargo test -p blossom-consensus --test hegel_trusted_network -- --nocapture

run_step trusted-checkpoint-dag-properties \
  cargo test -p blossom-consensus --features trusted-checkpoint-dag \
  trusted_dag::tests -- --nocapture

run_step trusted-checkpoint-dag-hegel \
  cargo test -p blossom-consensus --features trusted-checkpoint-dag \
  --test hegel_trusted_dag -- --nocapture

run_step parallel-ha-global-coordination \
  cargo test -p blossom-consensus --features parallel-networks \
  parallel_networks::tests -- --nocapture

run_step parallel-ha-global-hegel \
  cargo test -p blossom-consensus --features parallel-networks \
  --test hegel_parallel_networks -- --nocapture

run_step trusted-tcp \
  cargo test -p blossom-consensus --test e2e_tcp trusted_cluster_accepts_unsigned_block_and_dispatch \
  -- --nocapture

run_step trusted-hierarchical-tcp \
  cargo test -p blossom-bench-harness --lib \
  blossom_adapter::tests::trusted_tcp_cluster_orders_all_parallel_writer_blocks_by_hash \
  -- --nocapture

printf 'trusted production validation logs: %s\n' "$OUT_DIR"
