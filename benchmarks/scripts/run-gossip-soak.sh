#!/usr/bin/env bash
# Run repeated filtered-payload gossip validations for a fixed wall-clock time.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"
# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

mkdir -p "$root/results"
out="$root/results/gossip_soak_$(timestamp).csv"
duration="${DURATION_SECONDS:-1800}"
deadline=$((SECONDS + duration))

pinned_exec cargo build --release --features availability-gossip --bin blossom-gossip-bench

cases=(
  "36 64 4096 6 6"
  "37 64 4096 3 1"
  "73 64 4096 5 7"
  "72 128 4096 6 6"
  "17 32 1024 1 1"
  "73 16 1024 7 72"
)

iteration=0
while (( SECONDS < deadline )); do
  case="${cases[$((iteration % ${#cases[@]}))]}"
  read -r nodes entries payload_bytes fanout targets <<<"$case"

  args=(
    --nodes "$nodes"
    --entries "$entries"
    --payload-bytes "$payload_bytes"
    --fanout "$fanout"
    --targets-per-entry "$targets"
    --iterations 1
    --warmup 0
    --expect-complete
    --csv "$out"
    --append
  )

  if (( iteration % 2 == 1 )); then
    args+=(--trusted)
  fi

  echo "soak[$iteration]: nodes=$nodes entries=$entries bytes=$payload_bytes fanout=$fanout targets=$targets trusted=$((iteration % 2))"
  pinned_exec target/release/blossom-gossip-bench "${args[@]}"
  iteration=$((iteration + 1))
done

echo "ran $iteration soak iterations"
echo "wrote $out"
