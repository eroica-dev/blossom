#!/usr/bin/env bash
# Run a large transaction-count harness benchmark and write a timestamped CSV.
#
# Defaults are intentionally sized for a million small transactions on loopback.
#
# Environment:
#   NODES=6
#   TRANSACTIONS=1000000
#   TX_BYTES=32
#   APP_STATE_BYTES=0
#   ITERATIONS=1
#   WARMUP=0
#   DELIVERY_MODE=first-accepted   all-peers or first-accepted
#   TRUSTED=0
#   EXTERNAL_TRANSACTION_HASHES=0
#   BLOSSOM_MAX_FRAME_SIZE=1073741824
#   BLOSSOM_MAX_PENDING_RAW_DISPATCH_BYTES=536870912
#   BLOSSOM_MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER=134217728
#   SERVER_CPUSET=0-3         Linux only, optional taskset pinning.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"
# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

export BLOSSOM_MAX_FRAME_SIZE="${BLOSSOM_MAX_FRAME_SIZE:-1073741824}"
echo "wire max frame: $BLOSSOM_MAX_FRAME_SIZE bytes"

mkdir -p "$root/results"
out="$root/results/load_$(timestamp).csv"

if [[ "${DIRECT:-0}" == "1" ]]; then
  cargo build --release --bin blossom-harness-bench
  cmd=("$ws_root/target/release/blossom-harness-bench")
else
  cmd=(cargo run --release --bin blossom-harness-bench --)
fi
trusted_arg=()
if [[ "${TRUSTED:-0}" == "1" || "${TRUSTED:-false}" == "true" ]]; then
  trusted_arg=(--trusted)
fi
external_hash_arg=()
if [[ "${EXTERNAL_TRANSACTION_HASHES:-0}" == "1" || "${EXTERNAL_TRANSACTION_HASHES:-false}" == "true" ]]; then
  external_hash_arg=(--external-transaction-hashes)
fi

pinned_exec "${cmd[@]}" \
  --nodes "${NODES:-6}" \
  --transactions "${TRANSACTIONS:-1000000}" \
  --transaction-bytes "${TX_BYTES:-32}" \
  --application-state-bytes "${APP_STATE_BYTES:-0}" \
  --iterations "${ITERATIONS:-1}" \
  --warmup "${WARMUP:-0}" \
  --delivery-mode "${DELIVERY_MODE:-first-accepted}" \
  "${trusted_arg[@]}" \
  "${external_hash_arg[@]}" \
  --csv "$out"

echo "wrote $out"
