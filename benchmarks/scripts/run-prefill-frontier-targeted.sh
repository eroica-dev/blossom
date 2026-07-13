#!/usr/bin/env bash
# Run the sim-validated prefill-dispatch safety frontier cases.
#
# This is intentionally narrower than run-prefill-safety-matrix.sh. It repeats
# the edges that define the current route policy:
#   - small trustless q with Byzantine withholding fails closed,
#   - q5/q6/q8/q12 exercise future-route prefill under withholding,
#   - over-tolerance withholding fails closed.
#
# Environment:
#   OUT_DIR=benchmarks/results/prefill_frontier_targeted_YYYYMMDD_HHMMSS
#   REPEAT_RUNS=3
#   EPOCHS=100
#   COMMANDS_PER_NODE=256
#   COMMAND_BYTES=1024
#   TARGETS_PER_COMMAND=3
#   FEATURES="availability-gossip,propagation-adaptive"

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"

# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

timestamp_value="$(timestamp)"
out_dir="${OUT_DIR:-$root/results/prefill_frontier_targeted_${timestamp_value}}"
mkdir -p "$out_dir"

csv="$out_dir/subset_gossip_runs.csv"
manifest="$out_dir/prefill_safety_manifest.csv"
repeat_runs="${REPEAT_RUNS:-3}"
epochs="${EPOCHS:-100}"
commands_per_node="${COMMANDS_PER_NODE:-256}"
command_bytes="${COMMAND_BYTES:-1024}"
targets="${TARGETS_PER_COMMAND:-3}"
features="${FEATURES:-availability-gossip,propagation-adaptive}"
seed_base="${SEED_BASE:-709653441102}"
latency_seed_base="${LATENCY_SEED_BASE:-900337}"

printf 'scenario,architecture,repeat,nodes,quorum_size,targets_per_command,latency_profile,withholders_per_branch,expected_status,actual_status,stdout,stderr,seed,latency_seed\n' > "$manifest"

cargo build --release --features "$features" --bin blossom-subset-gossip-bench

run_case() {
  local label="$1"
  local repeat="$2"
  local nodes="$3"
  local quorum_size="$4"
  local withholders="$5"
  local latency_profile="$6"
  local expected_status="$7"
  shift 7

  local seed=$((seed_base + repeat * 1000003 + nodes * 9176 + quorum_size * 769 + withholders * 19))
  local latency_seed=$((latency_seed_base + repeat * 65537 + nodes * 4099 + quorum_size * 769))
  local scenario="${label}_${latency_profile}_n${nodes}_q${quorum_size}_w${withholders}_r${repeat}"
  local stdout="$out_dir/${scenario}.stdout"
  local stderr="$out_dir/${scenario}.stderr"

  set +e
  target/release/blossom-subset-gossip-bench \
    --scenario "$scenario" \
    --protocol-version v2 \
    --repeat "$repeat" \
    --nodes "$nodes" \
    --quorum-size "$quorum_size" \
    --epoch-depth "$epochs" \
    --commands-per-node "$commands_per_node" \
    --command-bytes "$command_bytes" \
    --targets-per-command "$targets" \
    --seed "$seed" \
    --latency-seed "$latency_seed" \
    --prefill-byzantine-withholders-per-branch "$withholders" \
    --expect-complete \
    --csv "$csv" \
    --append \
    "$@" > "$stdout" 2> "$stderr"
  local status=$?
  set -e

  local actual_status="pass"
  if [[ "$status" -ne 0 ]]; then
    actual_status="fail"
  fi

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$scenario" verified "$repeat" "$nodes" "$quorum_size" "$targets" "$latency_profile" \
    "$withholders" "$expected_status" "$actual_status" "$stdout" "$stderr" \
    "$seed" "$latency_seed" >> "$manifest"

  if [[ "$expected_status" != "$actual_status" ]]; then
    echo "scenario $scenario expected $expected_status but got $actual_status; see $stderr" >&2
    return 1
  fi
}

run_pair() {
  local label="$1"
  local repeat="$2"
  local nodes="$3"
  local quorum_size="$4"
  local withholders="$5"
  local expected_status="$6"

  run_case "$label" "$repeat" "$nodes" "$quorum_size" "$withholders" even150 "$expected_status" \
    --latency-distribution even \
    --latency-ms 150

  run_case "$label" "$repeat" "$nodes" "$quorum_size" "$withholders" random1_300 "$expected_status" \
    --latency-distribution random \
    --latency-min-ms 1 \
    --latency-max-ms 300
}

for repeat in $(seq 1 "$repeat_runs"); do
  run_pair valid_n36_q6_f1 "$repeat" 36 6 1 pass
  run_pair valid_n72_q5_f1 "$repeat" 72 5 1 pass
  run_pair valid_n72_q6_f1 "$repeat" 72 6 1 pass
  run_pair valid_n144_q8_f2 "$repeat" 144 8 2 pass
  run_pair valid_n144_q12_f3 "$repeat" 144 12 3 pass
  run_pair control_n144_q6_no_withholding "$repeat" 144 6 0 pass

  run_pair invalid_n72_q4_f1 "$repeat" 72 4 1 fail
  run_pair invalid_n72_q6_over_tolerance "$repeat" 72 6 2 fail
done

python3 "$here/analyze-subset-gossip.py" "$out_dir"
python3 "$here/analyze-prefill-safety.py" "$out_dir"

echo "wrote $out_dir"
