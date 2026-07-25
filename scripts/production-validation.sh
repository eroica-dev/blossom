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

run protocol-hardening-runtime cargo test -p blossom --lib runtime::tests

run protocol-hardening-tcp cargo test -p blossom --lib tcp::tests

run trusted-network-production-gate "$ROOT/scripts/trusted-production-validation.sh"

run tcp-finality-6-node cargo test --test e2e_tcp autonomous_tcp_driver_advances_all_nodes_through_epoch

run tcp-finality-36-node-v2 cargo test --test e2e_tcp autonomous_tcp_driver_finalizes_36_node_v2_two_round_epoch

run reconnect-and-byzantine-sim cargo run -p blossom-sim --bin blossom-sim-epoch-chaos --release -- \
  --nodes 36 \
  --epochs 128 \
  --transactions-per-node 4 \
  --transaction-bytes 1024 \
  --latency-ms 25 \
  --jitter-ms 10 \
  --drop-ppm 500 \
  --fuzz-ppm 100 \
  --repair-rounds 2 \
  --repair-fanout 30 \
  --repair-quorum 24 \
  --faulty-nodes 4 \
  --byzantine-nodes 4 \
  --drop-faulty-after-epochs 8 \
  --reconnect-dropped-after-epochs 16 \
  --reconnect-ping-fanout 30 \
  --reconnect-ping-quorum 24 \
  --reconnect-approval-quorum 24 \
  --max-reconnected-nodes-per-epoch 2 \
  --byzantine-reconnect-replay-ppm 250 \
  --byzantine-reconnect-stale-proof-ppm 250 \
  --byzantine-reconnect-sybil-ppm 250 \
  --seed 4242

run high-availability-production-gate "$ROOT/scripts/ha-production-validation.sh"

run latency-100ms-sim cargo run -p blossom-sim --bin blossom-sim-epoch-chaos --release -- \
  --nodes 36 \
  --epochs 64 \
  --transactions-per-node 4 \
  --transaction-bytes 1024 \
  --latency-ms 100 \
  --jitter-ms 25 \
  --drop-ppm 250 \
  --repair-rounds 2 \
  --repair-fanout 30 \
  --repair-quorum 24 \
  --faulty-nodes 2 \
  --byzantine-nodes 2 \
  --seed 4343

run proof-validation-matrix env \
  REPEAT_RUNS="${PROOF_REPEAT_RUNS:-1}" \
  EPOCHS="${PROOF_EPOCHS:-128}" \
  THROUGHPUT_EPOCHS="${PROOF_THROUGHPUT_EPOCHS:-128}" \
  TXS_PER_NODE="${PROOF_TXS_PER_NODE:-4}" \
  THROUGHPUT_TXS_PER_NODE="${PROOF_THROUGHPUT_TXS_PER_NODE:-128}" \
  "$ROOT/benchmarks/scripts/run-proof-validation-matrix.sh"

echo "production validation logs: $OUT_DIR"
