#!/usr/bin/env bash
# Run a correctness/performance matrix for filtered-payload gossip.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"
# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

mkdir -p "$root/results"
out="$root/results/gossip_matrix_$(timestamp).csv"
iterations="${ITERATIONS:-2}"
warmup="${WARMUP:-0}"
profile="${MATRIX_PROFILE:-quick}"

pinned_exec cargo build --release --features availability-gossip --bin blossom-gossip-bench

run_case() {
  local nodes="$1"
  local entries="$2"
  local payload_bytes="$3"
  local fanout="$4"
  local targets="$5"
  local trusted="$6"
  local single_fetch="$7"

  local args=(
    --nodes "$nodes"
    --entries "$entries"
    --payload-bytes "$payload_bytes"
    --fanout "$fanout"
    --targets-per-entry "$targets"
    --iterations "$iterations"
    --warmup "$warmup"
    --expect-complete
    --csv "$out"
    --append
  )

  if [[ "$trusted" == "1" ]]; then
    args+=(--trusted)
  fi
  if [[ "$single_fetch" == "1" ]]; then
    args+=(--single-fetch)
  fi

  echo "matrix: nodes=$nodes entries=$entries bytes=$payload_bytes fanout=$fanout targets=$targets trusted=$trusted single_fetch=$single_fetch"
  pinned_exec target/release/blossom-gossip-bench "${args[@]}"
}

cases=(
  "36 64 4096 6 6"
  "37 64 4096 3 1"
  "73 64 4096 5 7"
  "17 32 1024 1 1"
  "73 16 1024 7 72"
)

if [[ "$profile" == "full" ]]; then
  cases+=(
    "72 128 4096 6 6"
    "73 128 4096 6 6"
    "97 64 4096 7 9"
  )
fi

for case in "${cases[@]}"; do
  read -r nodes entries payload_bytes fanout targets <<<"$case"
  run_case "$nodes" "$entries" "$payload_bytes" "$fanout" "$targets" 0 0
  run_case "$nodes" "$entries" "$payload_bytes" "$fanout" "$targets" 1 0
done

# Keep the slower single-fetch equivalence check small by default.
run_case 37 32 1024 3 1 0 1
run_case 37 32 1024 3 1 1 1

echo "wrote $out"
