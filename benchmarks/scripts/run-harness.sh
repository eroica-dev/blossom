#!/usr/bin/env bash
# Run one local TCP harness benchmark and write a timestamped CSV.
#
# Environment:
#   NODES=6
#   TRANSACTIONS=3
#   TX_BYTES=32
#   ITERATIONS=10
#   WARMUP=1
#   DELIVERY_MODE=all-peers   all-peers or first-accepted
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
out="$root/results/harness_$(timestamp).csv"

if [[ "${DIRECT:-0}" == "1" ]]; then
  cargo build --release --bin blossom-harness-bench
  cmd=("$ws_root/target/release/blossom-harness-bench")
else
  cmd=(cargo run --release --bin blossom-harness-bench --)
fi

pinned_exec "${cmd[@]}" \
  --nodes "${NODES:-6}" \
  --transactions "${TRANSACTIONS:-3}" \
  --transaction-bytes "${TX_BYTES:-32}" \
  --iterations "${ITERATIONS:-10}" \
  --warmup "${WARMUP:-1}" \
  --delivery-mode "${DELIVERY_MODE:-all-peers}" \
  --csv "$out"

echo "wrote $out"
