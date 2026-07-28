#!/usr/bin/env bash
# Run repeated long-horizon epoch throughput, latency, and network-size checks.
#
# Protocol fault simulation is owned by eden-dev-inc/deterministic-simulation.
#
# Environment:
#   OUT_DIR=benchmarks/results/proof_validation_YYYYMMDD_HHMMSS
#   REPEAT_RUNS=3
#   THROUGHPUT_EPOCHS=2000
#   THROUGHPUT_TXS_PER_NODE=1000
#   THROUGHPUT_TX_BYTES=32
#   LATENCY_SEED_BASE=781273

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"

# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

timestamp_value="$(timestamp)"
out_dir="${OUT_DIR:-$root/results/proof_validation_${timestamp_value}}"
mkdir -p "$out_dir"

repeat_runs="${REPEAT_RUNS:-3}"
throughput_epochs="${THROUGHPUT_EPOCHS:-2000}"
throughput_txs_per_node="${THROUGHPUT_TXS_PER_NODE:-1000}"
throughput_tx_bytes="${THROUGHPUT_TX_BYTES:-32}"
latency_seed_base="${LATENCY_SEED_BASE:-781273}"

if ((repeat_runs < 1)); then
  echo "REPEAT_RUNS must be >= 1" >&2
  exit 1
fi

cargo build --release --bin blossom-epoch-bench

manifest="$out_dir/run_manifest.csv"
printf 'scenario,architecture,repeat,latency_profile,nodes,csv,stderr,latency_seed\n' >"$manifest"
scenario_counter=0

run_throughput() {
  local architecture="$1"
  local nodes="$2"
  local latency_profile="$3"
  local repeat="$4"
  shift 4

  scenario_counter=$((scenario_counter + 1))
  local latency_seed=$((latency_seed_base + repeat * 65537 + scenario_counter * 4099))
  local scenario="throughput_${architecture}_${latency_profile}_n${nodes}_r${repeat}"
  local csv="$out_dir/${scenario}.csv"
  local stderr_log="$out_dir/${scenario}.stderr"
  local trusted_arg=()
  if [[ "$architecture" == "trusted" ]]; then
    trusted_arg=(--trusted)
  fi

  target/release/blossom-epoch-bench \
    --nodes "$nodes" \
    --quorum-size 6 \
    --epoch-depth "$throughput_epochs" \
    --transactions-per-node "$throughput_txs_per_node" \
    --transaction-bytes "$throughput_tx_bytes" \
    --latency-seed "$latency_seed" \
    --csv "$csv" \
    ${trusted_arg[@]+"${trusted_arg[@]}"} \
    "$@" >"$out_dir/${scenario}.stdout" 2>"$stderr_log"

  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$scenario" "$architecture" "$repeat" "$latency_profile" "$nodes" \
    "$csv" "$stderr_log" "$latency_seed" >>"$manifest"
}

for repeat in $(seq 1 "$repeat_runs"); do
  for nodes in 6 12 36 64; do
    for architecture in verified trusted; do
      run_throughput "$architecture" "$nodes" even150 "$repeat" \
        --latency-distribution even \
        --latency-ms 150
      run_throughput "$architecture" "$nodes" random1_300 "$repeat" \
        --latency-distribution random \
        --latency-min-ms 1 \
        --latency-max-ms 300
    done
  done

  for nodes in 36 64; do
    for architecture in verified trusted; do
      run_throughput "$architecture" "$nodes" even50 "$repeat" \
        --latency-distribution even \
        --latency-ms 50
      run_throughput "$architecture" "$nodes" even300 "$repeat" \
        --latency-distribution even \
        --latency-ms 300
    done
  done
done

echo "wrote $out_dir"
