#!/usr/bin/env bash
# Run the paper-aligned epoch benchmark across quorum sizes and latency models.
#
# Defaults run 100 epochs for q={3,6,9,12}. Node count defaults to q*q so each
# quorum size exercises two topology rounds with square, non-degenerate groups.
#
# Environment:
#   EPOCH_DEPTH=100
#   BLOSSOM_QUORUM_SIZES="3 6 9 12"
#   QUORUM_SIZES=               temporary compatibility alias
#   LATENCY_DISTRIBUTIONS="even random"
#   TRUSTED_MODES="0 1"          0=trustless/verified, 1=trusted
#   NODES=                       optional; when unset uses quorum_size^2
#   TXS_PER_NODE=1000
#   TX_BYTES=32
#   APP_STATE_BYTES=0
#   EVEN_LATENCY_MS=150
#   RANDOM_LATENCY_MIN_MS=1
#   RANDOM_LATENCY_MAX_MS=300
#   LATENCY_SEED=781273
#   SHUFFLE=0
#   DIRECT=0

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"
# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

mkdir -p "$root/results"
out="$root/results/epoch_latency_matrix_$(timestamp).csv"

if [[ "${DIRECT:-0}" == "1" ]]; then
  cargo build --release --bin blossom-epoch-bench
  cmd=("$ws_root/target/release/blossom-epoch-bench")
else
  cmd=(cargo run --release --bin blossom-epoch-bench --)
fi

quorum_sizes="${BLOSSOM_QUORUM_SIZES:-${QUORUM_SIZES:-3 6 9 12}}"
for quorum_size in $quorum_sizes; do
  nodes="${NODES:-$((quorum_size * quorum_size))}"
  for distribution in ${LATENCY_DISTRIBUTIONS:-even random}; do
    for trusted_mode in ${TRUSTED_MODES:-0 1}; do
      args=(
        --nodes "$nodes"
        --quorum-size "$quorum_size"
        --epoch-depth "${EPOCH_DEPTH:-100}"
        --transactions-per-node "${TXS_PER_NODE:-1000}"
        --transaction-bytes "${TX_BYTES:-32}"
        --application-state-bytes "${APP_STATE_BYTES:-0}"
        --latency-distribution "$distribution"
        --latency-ms "${EVEN_LATENCY_MS:-150}"
        --latency-min-ms "${RANDOM_LATENCY_MIN_MS:-1}"
        --latency-max-ms "${RANDOM_LATENCY_MAX_MS:-300}"
        --latency-seed "${LATENCY_SEED:-781273}"
        --append
        --csv "$out"
      )

      if [[ "${SHUFFLE:-0}" == "1" || "${SHUFFLE:-false}" == "true" ]]; then
        args+=(--shuffle)
      fi
      if [[ "$trusted_mode" == "1" || "$trusted_mode" == "true" || "$trusted_mode" == "trusted" ]]; then
        args+=(--trusted)
      fi

      pinned_exec "${cmd[@]}" "${args[@]}"
    done
  done
done

echo "wrote $out"
