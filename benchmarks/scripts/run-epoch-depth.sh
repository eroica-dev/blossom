#!/usr/bin/env bash
# Run a paper-aligned in-memory epoch-depth benchmark.
#
# Environment:
#   NODES=36
#   EPOCH_DEPTH=1
#   TARGET_TRANSACTIONS=1000000   optional; derives epoch depth from cap
#   TXS_PER_NODE=1000
#   TX_BYTES=32
#   SHUFFLE=0                     set to 1 for seed-driven epoch shuffling
#   SERVER_CPUSET=0-3             Linux only, optional taskset pinning.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"
# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

mkdir -p "$root/results"
out="$root/results/epoch_depth_$(timestamp).csv"

if [[ "${DIRECT:-0}" == "1" ]]; then
  cargo build --release --bin blossom-epoch-bench
  cmd=("$ws_root/target/release/blossom-epoch-bench")
else
  cmd=(cargo run --release --bin blossom-epoch-bench --)
fi

args=(
  --nodes "${NODES:-36}"
  --epoch-depth "${EPOCH_DEPTH:-1}"
  --transactions-per-node "${TXS_PER_NODE:-1000}"
  --transaction-bytes "${TX_BYTES:-32}"
  --csv "$out"
)

if [[ -n "${TARGET_TRANSACTIONS:-}" ]]; then
  args+=(--target-transactions "$TARGET_TRANSACTIONS")
fi

if [[ "${SHUFFLE:-0}" == "1" ]]; then
  args+=(--shuffle)
fi

pinned_exec "${cmd[@]}" "${args[@]}"

echo "wrote $out"
