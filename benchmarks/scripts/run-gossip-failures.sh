#!/usr/bin/env bash
# Run deterministic failure-mode probes for filtered-payload gossip.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"
# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

mkdir -p "$root/results"
out="$root/results/gossip_failures_$(timestamp).csv"

pinned_exec cargo build --release --features availability-gossip --bin blossom-gossip-bench

echo "failure: total gossip blackout should leave the cluster incomplete"
pinned_exec target/release/blossom-gossip-bench \
  --nodes "${NODES:-37}" \
  --entries "${ENTRIES:-64}" \
  --payload-bytes "${PAYLOAD_BYTES:-4096}" \
  --fanout "${FANOUT:-3}" \
  --targets-per-entry "${TARGETS_PER_ENTRY:-1}" \
  --iterations "${ITERATIONS:-2}" \
  --warmup "${WARMUP:-0}" \
  --drop-gossip-every 1 \
  --csv "$out" \
  --append

awk -F, '
  NR == 1 { next }
  {
    rows += 1
    if ($26 >= $2) {
      printf "expected incomplete dissemination, got %s/%s nodes\n", $26, $2 > "/dev/stderr"
      exit 1
    }
    if ($27 <= 0) {
      printf "expected dropped gossip sends, got %s\n", $27 > "/dev/stderr"
      exit 1
    }
  }
  END {
    if (rows == 0) {
      print "no failure rows were written" > "/dev/stderr"
      exit 1
    }
  }
' "$out"

echo "failure validation passed"
echo "wrote $out"
