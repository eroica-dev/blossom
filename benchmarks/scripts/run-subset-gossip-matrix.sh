#!/usr/bin/env bash
# Run repeated full-replication vs recipient-filtered subset block gossip tests.
#
# Environment:
#   OUT_DIR=benchmarks/results/subset_gossip_YYYYMMDD_HHMMSS
#   REPEAT_RUNS=3
#   EPOCHS=100
#   COMMANDS_PER_NODE=256
#   COMMAND_BYTES=1024
#   QUORUM_SIZE=6

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"

# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

timestamp_value="$(timestamp)"
out_dir="${OUT_DIR:-$root/results/subset_gossip_${timestamp_value}}"
mkdir -p "$out_dir"

csv="$out_dir/subset_gossip_runs.csv"
repeat_runs="${REPEAT_RUNS:-3}"
epochs="${EPOCHS:-100}"
commands_per_node="${COMMANDS_PER_NODE:-256}"
command_bytes="${COMMAND_BYTES:-1024}"
quorum_size="${QUORUM_SIZE:-6}"
seed_base="${SEED_BASE:-708026904833}"
latency_seed_base="${LATENCY_SEED_BASE:-918273645}"

cargo build --release --features availability-gossip --bin blossom-subset-gossip-bench

run_case() {
  local nodes="$1"
  local targets="$2"
  local architecture="$3"
  local latency_profile="$4"
  local repeat="$5"
  shift 5

  local trusted_arg=()
  if [[ "$architecture" == "trusted" ]]; then
    trusted_arg=(--trusted)
  fi

  local seed=$((seed_base + repeat * 1000003 + nodes * 9176 + targets * 131))
  local latency_seed=$((latency_seed_base + repeat * 65537 + nodes * 4099 + targets * 257))
  local scenario="subset_${architecture}_${latency_profile}_n${nodes}_t${targets}_r${repeat}"

  echo "subset matrix: scenario=$scenario epochs=$epochs commands_per_node=$commands_per_node command_bytes=$command_bytes"
  target/release/blossom-subset-gossip-bench \
    --scenario "$scenario" \
    --repeat "$repeat" \
    --nodes "$nodes" \
    --quorum-size "$quorum_size" \
    --epoch-depth "$epochs" \
    --commands-per-node "$commands_per_node" \
    --command-bytes "$command_bytes" \
    --targets-per-command "$targets" \
    --seed "$seed" \
    --latency-seed "$latency_seed" \
    --expect-complete \
    --csv "$csv" \
    --append \
    ${trusted_arg[@]+"${trusted_arg[@]}"} \
    "$@" > "$out_dir/${scenario}.stdout" 2> "$out_dir/${scenario}.stderr"
}

for repeat in $(seq 1 "$repeat_runs"); do
  for nodes in 12 36 64; do
    for targets in 1 3 6; do
      for architecture in verified trusted; do
        run_case "$nodes" "$targets" "$architecture" even150 "$repeat" \
          --latency-distribution even \
          --latency-ms 150

        run_case "$nodes" "$targets" "$architecture" random1_300 "$repeat" \
          --latency-distribution random \
          --latency-min-ms 1 \
          --latency-max-ms 300
      done
    done
  done
done

python3 "$here/analyze-subset-gossip.py" "$out_dir"

echo "wrote $out_dir"
