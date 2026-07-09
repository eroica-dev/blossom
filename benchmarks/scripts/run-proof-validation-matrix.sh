#!/usr/bin/env bash
# Run repeated long-horizon proof-boundary validation for Blossom.
#
# The matrix intentionally separates:
#   1. epoch-chaos correctness/fault-tolerance/finality runs; and
#   2. epoch-depth throughput/latency/network-size runs.
#
# Environment:
#   OUT_DIR=benchmarks/results/proof_validation_YYYYMMDD_HHMMSS
#   REPEAT_RUNS=3                 supported study range: 3-5
#   EPOCHS=2000
#   THROUGHPUT_EPOCHS=2000
#   TXS_PER_NODE=8
#   TX_BYTES=32
#   THROUGHPUT_TXS_PER_NODE=1000
#   THROUGHPUT_TX_BYTES=32
#   SEED_BASE=7308332182487356264
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
epochs="${EPOCHS:-2000}"
throughput_epochs="${THROUGHPUT_EPOCHS:-2000}"
txs_per_node="${TXS_PER_NODE:-8}"
tx_bytes="${TX_BYTES:-32}"
throughput_txs_per_node="${THROUGHPUT_TXS_PER_NODE:-1000}"
throughput_tx_bytes="${THROUGHPUT_TX_BYTES:-32}"
seed_base="${SEED_BASE:-7308332182487356264}"
latency_seed_base="${LATENCY_SEED_BASE:-781273}"

if (( repeat_runs < 1 )); then
  echo "REPEAT_RUNS must be >= 1" >&2
  exit 1
fi

cargo build --release -p blossom-sim --bin blossom-sim-epoch-chaos
cargo build --release --bin blossom-epoch-bench

manifest="$out_dir/run_manifest.csv"
printf 'kind,base_scenario,scenario,architecture,repeat,latency_profile,nodes,expected_status,actual_status,summary,epochs,stages,stderr,seed,latency_seed\n' > "$manifest"

scenario_counter=0

run_chaos() {
  local base_scenario="$1"
  local architecture="$2"
  local nodes="$3"
  local expected_status="$4"
  local repeat="$5"
  shift 5

  scenario_counter=$((scenario_counter + 1))
  local seed=$((seed_base + repeat * 1000003 + scenario_counter * 9176))
  local scenario="${base_scenario}_${architecture}_n${nodes}_r${repeat}"
  local summary="$out_dir/${scenario}_summary.csv"
  local epoch_log="$out_dir/${scenario}_epochs.csv"
  local stage_log="$out_dir/${scenario}_stages.csv"
  local stderr_log="$out_dir/${scenario}.stderr"

  set +e
  target/release/blossom-sim-epoch-chaos \
    --nodes "$nodes" \
    --epochs "$epochs" \
    --transactions-per-node "$txs_per_node" \
    --transaction-bytes "$tx_bytes" \
    --seed "$seed" \
    --csv "$summary" \
    --epoch-log "$epoch_log" \
    --stage-log "$stage_log" \
    "$@" > "$out_dir/${scenario}.stdout" 2> "$stderr_log"
  local status=$?
  set -e

  local actual_status="pass"
  if [[ "$status" -ne 0 ]]; then
    actual_status="fail"
  fi

  printf 'chaos,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,\n' \
    "$base_scenario" "$scenario" "$architecture" "$repeat" "modeled" "$nodes" \
    "$expected_status" "$actual_status" "$summary" "$epoch_log" "$stage_log" \
    "$stderr_log" "$seed" >> "$manifest"

  if [[ "$expected_status" == "pass" && "$actual_status" != "pass" ]]; then
    echo "scenario $scenario failed unexpectedly; see $stderr_log" >&2
    return "$status"
  fi
  if [[ "$expected_status" == "fail" && "$actual_status" != "fail" ]]; then
    echo "scenario $scenario passed unexpectedly; expected validation failure" >&2
    return 1
  fi
}

run_throughput() {
  local base_scenario="$1"
  local architecture="$2"
  local nodes="$3"
  local latency_profile="$4"
  local repeat="$5"
  shift 5

  scenario_counter=$((scenario_counter + 1))
  local seed=$((seed_base + repeat * 1000003 + scenario_counter * 9176))
  local latency_seed=$((latency_seed_base + repeat * 65537 + scenario_counter * 4099))
  local scenario="${base_scenario}_${architecture}_${latency_profile}_n${nodes}_r${repeat}"
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
    "$@" > "$out_dir/${scenario}.stdout" 2> "$stderr_log"

  printf 'throughput,%s,%s,%s,%s,%s,%s,pass,pass,%s,,,%s,%s,%s\n' \
    "$base_scenario" "$scenario" "$architecture" "$repeat" "$latency_profile" "$nodes" \
    "$csv" "$stderr_log" "$seed" "$latency_seed" >> "$manifest"
}

run_architecture_chaos_suite() {
  local architecture="$1"
  local repeat="$2"
  local trusted_arg=()
  if [[ "$architecture" == "trusted" ]]; then
    trusted_arg=(--trusted)
  fi

  for nodes in 6 12 36 64; do
    run_chaos "clean" "$architecture" "$nodes" pass "$repeat" \
      --repair-rounds 2 \
      ${trusted_arg[@]+"${trusted_arg[@]}"}
  done

  for nodes in 36 64; do
    run_chaos "fault_repair" "$architecture" "$nodes" pass "$repeat" \
      --latency-ms 20 \
      --jitter-ms 20 \
      --drop-ppm 10000 \
      --fuzz-ppm 1000 \
      --spike-ppm 30000 \
      --spike-latency-ms 250 \
      --repair-rounds 4 \
      --require-reconciliation \
      ${trusted_arg[@]+"${trusted_arg[@]}"}
  done

  run_chaos "roundskip_first_fanout" "$architecture" 36 pass "$repeat" \
    --assist-after-skipped-round 0 \
    --repair-rounds 4 \
    ${trusted_arg[@]+"${trusted_arg[@]}"}

  run_chaos "roundskip_after_first_fanout" "$architecture" 36 pass "$repeat" \
    --assist-after-skipped-round 1 \
    --repair-rounds 4 \
    --require-reconciliation \
    ${trusted_arg[@]+"${trusted_arg[@]}"}

  for nodes in 36 64; do
    run_chaos "fault_churn" "$architecture" "$nodes" pass "$repeat" \
      --latency-ms 20 \
      --jitter-ms 20 \
      --faulty-nodes 4 \
      --drop-faulty-after-epochs 2 \
      --max-dropped-nodes-per-epoch 2 \
      --min-active-nodes $((nodes - 6)) \
      --reconnect-dropped-after-epochs 5 \
      --max-reconnected-nodes-per-epoch 2 \
      --repair-rounds 4 \
      ${trusted_arg[@]+"${trusted_arg[@]}"}
  done

  run_chaos "partition_reconnect" "$architecture" 36 pass "$repeat" \
    --faulty-nodes 4 \
    --drop-faulty-after-epochs 2 \
    --max-dropped-nodes-per-epoch 2 \
    --min-active-nodes 30 \
    --reconnect-dropped-after-epochs 3 \
    --max-reconnected-nodes-per-epoch 2 \
    --partition-start-epoch 2 \
    --partition-end-epoch 800 \
    --partition-left-nodes 12 \
    --partition-reconnect-only \
    --repair-rounds 4 \
    ${trusted_arg[@]+"${trusted_arg[@]}"}
}

run_verified_byzantine_suite() {
  local repeat="$1"

  run_chaos "byzantine_at_f" verified 6 pass "$repeat" \
    --byzantine-nodes 1 \
    --repair-rounds 2

  run_chaos "byzantine_at_f" verified 36 pass "$repeat" \
    --byzantine-nodes 11 \
    --repair-rounds 2

  for nodes in 36 64; do
    run_chaos "byzantine_churn" verified "$nodes" pass "$repeat" \
      --latency-ms 20 \
      --jitter-ms 20 \
      --faulty-nodes 4 \
      --drop-faulty-after-epochs 2 \
      --max-dropped-nodes-per-epoch 2 \
      --min-active-nodes $((nodes - 6)) \
      --reconnect-dropped-after-epochs 5 \
      --max-reconnected-nodes-per-epoch 2 \
      --byzantine-nodes 4 \
      --byzantine-reconnect-replay-ppm 50000 \
      --byzantine-reconnect-stale-proof-ppm 20000 \
      --byzantine-reconnect-sybil-ppm 20000 \
      --byzantine-duplicate-vote-copies 3 \
      --repair-rounds 4
  done

  run_chaos "reject_byzantine_over_f" verified 36 fail "$repeat" \
    --byzantine-nodes 12

  run_chaos "reject_low_repair_quorum" verified 36 fail "$repeat" \
    --repair-rounds 1 \
    --repair-quorum 23

  run_chaos "reject_low_reconnect_quorum" verified 36 fail "$repeat" \
    --faulty-nodes 1 \
    --reconnect-dropped-after-epochs 1 \
    --reconnect-ping-quorum 23 \
    --reconnect-approval-quorum 23
}

run_throughput_suite() {
  local repeat="$1"

  for nodes in 6 12 36 64; do
    for architecture in verified trusted; do
      run_throughput "throughput" "$architecture" "$nodes" even150 "$repeat" \
        --latency-distribution even \
        --latency-ms 150

      run_throughput "throughput" "$architecture" "$nodes" random1_300 "$repeat" \
        --latency-distribution random \
        --latency-min-ms 1 \
        --latency-max-ms 300
    done
  done

  for nodes in 36 64; do
    for architecture in verified trusted; do
      run_throughput "throughput" "$architecture" "$nodes" even50 "$repeat" \
        --latency-distribution even \
        --latency-ms 50

      run_throughput "throughput" "$architecture" "$nodes" even300 "$repeat" \
        --latency-distribution even \
        --latency-ms 300
    done
  done
}

for repeat in $(seq 1 "$repeat_runs"); do
  run_architecture_chaos_suite verified "$repeat"
  run_architecture_chaos_suite trusted "$repeat"
  run_verified_byzantine_suite "$repeat"
  run_throughput_suite "$repeat"
done

echo "wrote $out_dir"
