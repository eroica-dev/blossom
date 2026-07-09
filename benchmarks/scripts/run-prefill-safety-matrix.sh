#!/usr/bin/env bash
# Run repeated prefill-dispatch route-withholding safety checks.
#
# This matrix focuses on the v2 correctness claim that prefill-dispatch can
# skip the old first consensus round without relying on repair, while retaining
# at least one honest holder per future branch when one routed holder withholds.
#
# Environment:
#   OUT_DIR=benchmarks/results/prefill_safety_YYYYMMDD_HHMMSS
#   REPEAT_RUNS=3
#   EPOCHS=50
#   COMMANDS_PER_NODE=256
#   COMMAND_BYTES=1024
#   QUORUM_SIZES="6"
#   NODES="36 64 72"
#   TARGETS_PER_COMMAND="3 6"
#   WITHHOLDERS_PER_BRANCH="1"
#   ARCHITECTURES="verified"
#   FEATURES="availability-gossip,propagation-adaptive"
#   RUN_UNSAFE_NEGATIVE=1

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"

# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

timestamp_value="$(timestamp)"
out_dir="${OUT_DIR:-$root/results/prefill_safety_${timestamp_value}}"
mkdir -p "$out_dir"

csv="$out_dir/subset_gossip_runs.csv"
manifest="$out_dir/prefill_safety_manifest.csv"
repeat_runs="${REPEAT_RUNS:-3}"
epochs="${EPOCHS:-50}"
commands_per_node="${COMMANDS_PER_NODE:-256}"
command_bytes="${COMMAND_BYTES:-1024}"
features="${FEATURES:-availability-gossip,propagation-adaptive}"
seed_base="${SEED_BASE:-109739347944}"
latency_seed_base="${LATENCY_SEED_BASE:-612531}"

printf 'scenario,architecture,repeat,nodes,quorum_size,targets_per_command,latency_profile,withholders_per_branch,expected_status,actual_status,stdout,stderr,seed,latency_seed\n' > "$manifest"

cargo build --release --features "$features" --bin blossom-subset-gossip-bench

expected_status_for() {
  local architecture="$1"
  local nodes="$2"
  local quorum_size="$3"
  local withholders="$4"

  if [[ "$architecture" == "trusted" ]]; then
    echo "pass"
    return
  fi

  local tolerated=$(((quorum_size - 1) / 3))
  if (( withholders > 0 && quorum_size < 5 )); then
    echo "fail"
  elif (( withholders <= tolerated )); then
    echo "pass"
  else
    echo "fail"
  fi
}

run_case() {
  local scenario_base="$1"
  local architecture="$2"
  local repeat="$3"
  local nodes="$4"
  local quorum_size="$5"
  local targets="$6"
  local latency_profile="$7"
  local withholders="$8"
  local expected_status="$9"
  shift 9

  local trusted_arg=()
  if [[ "$architecture" == "trusted" ]]; then
    trusted_arg=(--trusted)
  fi

  local seed=$((seed_base + repeat * 1000003 + nodes * 9176 + quorum_size * 769 + targets * 131 + withholders * 19))
  local latency_seed=$((latency_seed_base + repeat * 65537 + nodes * 4099 + quorum_size * 769 + targets * 257))
  local scenario="${scenario_base}_${architecture}_${latency_profile}_n${nodes}_q${quorum_size}_t${targets}_w${withholders}_r${repeat}"
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
    ${trusted_arg[@]+"${trusted_arg[@]}"} \
    "$@" > "$stdout" 2> "$stderr"
  local status=$?
  set -e

  local actual_status="pass"
  if [[ "$status" -ne 0 ]]; then
    actual_status="fail"
  fi

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$scenario" "$architecture" "$repeat" "$nodes" "$quorum_size" "$targets" "$latency_profile" \
    "$withholders" "$expected_status" "$actual_status" "$stdout" "$stderr" \
    "$seed" "$latency_seed" >> "$manifest"

  if [[ "$expected_status" != "any" && "$expected_status" != "$actual_status" ]]; then
    echo "scenario $scenario expected $expected_status but got $actual_status; see $stderr" >&2
    return 1
  fi
}

for repeat in $(seq 1 "$repeat_runs"); do
  for nodes in ${NODES:-36 64 72}; do
    for quorum_size in ${QUORUM_SIZES:-6}; do
      for targets in ${TARGETS_PER_COMMAND:-3 6}; do
        for architecture in ${ARCHITECTURES:-verified}; do
          for withholders in ${WITHHOLDERS_PER_BRANCH:-1}; do
            expected_status="$(expected_status_for "$architecture" "$nodes" "$quorum_size" "$withholders")"
            run_case "v2_withholder" "$architecture" "$repeat" "$nodes" "$quorum_size" "$targets" even150 "$withholders" "$expected_status" \
              --latency-distribution even \
              --latency-ms 150

            run_case "v2_withholder" "$architecture" "$repeat" "$nodes" "$quorum_size" "$targets" random1_300 "$withholders" "$expected_status" \
              --latency-distribution random \
              --latency-min-ms 1 \
              --latency-max-ms 300
          done
        done
      done
    done
  done
done

if [[ "${RUN_UNSAFE_NEGATIVE:-1}" == "1" ]]; then
  run_case "unsafe_over_tolerance_withholder" verified 1 36 6 3 even150 2 fail \
    --latency-distribution even \
    --latency-ms 150
fi

python3 "$here/analyze-subset-gossip.py" "$out_dir"
python3 "$here/analyze-prefill-safety.py" "$out_dir"

echo "wrote $out_dir"
