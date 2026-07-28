#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/target/production-validation}"
mkdir -p "$OUT_DIR"

run() {
  local name="$1"
  shift
  echo "==> $name"
  "$@" >"$OUT_DIR/$name.log" 2>&1
  echo "ok: $name"
}

run cargo-test-workspace cargo test --workspace

run protocol-hardening-runtime cargo test -p blossom-consensus --lib runtime::tests

run protocol-hardening-tcp cargo test -p blossom-consensus --lib tcp::tests

run trusted-network-production-gate "$ROOT/scripts/trusted-production-validation.sh"

run tcp-finality-6-node cargo test --test e2e_tcp autonomous_tcp_driver_advances_all_nodes_through_epoch

run tcp-finality-36-node-v2 cargo test --test e2e_tcp autonomous_tcp_driver_finalizes_36_node_v2_two_round_epoch

run high-availability-production-gate "$ROOT/scripts/ha-production-validation.sh"

run proof-validation-matrix env \
  REPEAT_RUNS="${PROOF_REPEAT_RUNS:-1}" \
  THROUGHPUT_EPOCHS="${PROOF_THROUGHPUT_EPOCHS:-128}" \
  THROUGHPUT_TXS_PER_NODE="${PROOF_THROUGHPUT_TXS_PER_NODE:-128}" \
  "$ROOT/benchmarks/scripts/run-proof-validation-matrix.sh"

echo "production validation logs: $OUT_DIR"
