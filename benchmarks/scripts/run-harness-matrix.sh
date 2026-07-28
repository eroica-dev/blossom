#!/usr/bin/env bash
# Run a harness benchmark matrix over node counts and transaction counts.
#
# Environment:
#   NODE_COUNTS="1 6 12"
#   TRANSACTION_COUNTS="0 3 32"
#   TX_BYTES=32
#   APP_STATE_BYTES=0
#   ITERATIONS=5
#   WARMUP=1
#   DELIVERY_MODE=all-peers   all-peers or first-accepted
#   TRUSTED=0                 1 to run the known-member trusted path
#   EXTERNAL_TRANSACTION_HASHES=0
#   SERVER_CPUSET=0-3      Linux only, optional taskset pinning.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"
# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

mkdir -p "$root/results"
out="$root/results/harness_matrix_$(timestamp).csv"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

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

first=1
for nodes in ${NODE_COUNTS:-1 6 12}; do
  for txs in ${TRANSACTION_COUNTS:-0 3 32}; do
    echo "running nodes=$nodes transactions=$txs"
    pinned_exec "${cmd[@]}" \
      --nodes "$nodes" \
      --transactions "$txs" \
      --transaction-bytes "${TX_BYTES:-32}" \
      --application-state-bytes "${APP_STATE_BYTES:-0}" \
      --iterations "${ITERATIONS:-5}" \
      --warmup "${WARMUP:-1}" \
      --delivery-mode "${DELIVERY_MODE:-all-peers}" \
      ${trusted_arg[@]+"${trusted_arg[@]}"} \
      ${external_hash_arg[@]+"${external_hash_arg[@]}"} \
      --csv "$tmp"
    if [[ "$first" == "1" ]]; then
      cat "$tmp" > "$out"
      first=0
    else
      tail -n +2 "$tmp" >> "$out"
    fi
  done
done

echo "wrote $out"
