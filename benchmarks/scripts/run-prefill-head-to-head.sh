#!/usr/bin/env bash
# Run protocol v1 and protocol v2 prefill-dispatch head to head.
#
# The matrix writes one shared subset_gossip_runs.csv so
# analyze-subset-gossip.py can compare v2 to v1 with identical seeds,
# network size, target fanout, latency profile, and fault profile.
#
# Environment:
#   OUT_DIR=benchmarks/results/prefill_head_to_head_YYYYMMDD_HHMMSS
#   REPEAT_RUNS=3
#   EPOCHS=50
#   NODES="36 64 72"
#   QUORUM_SIZES="6"
#   TARGETS_PER_COMMAND="3 6"
#   LATENCY_PROFILES="even150 random1_300"
#   FAULT_PROFILES="clean round0_drop prefill_withhold"
#   ARCHITECTURES="verified"
#   WITHHOLDERS_PER_BRANCH=1
#   FEATURES="availability-gossip,propagation-adaptive"
#   EXPECT_COMPLETE=0

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"

# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

timestamp_value="$(timestamp)"
out_dir="${OUT_DIR:-$root/results/prefill_head_to_head_${timestamp_value}}"
mkdir -p "$out_dir"

csv="$out_dir/subset_gossip_runs.csv"
manifest="$out_dir/prefill_head_to_head_manifest.csv"
repeat_runs="${REPEAT_RUNS:-3}"
epochs="${EPOCHS:-50}"
commands_per_node="${COMMANDS_PER_NODE:-256}"
command_bytes="${COMMAND_BYTES:-1024}"
features="${FEATURES:-availability-gossip,propagation-adaptive}"
seed_base="${SEED_BASE:-78037124501}"
latency_seed_base="${LATENCY_SEED_BASE:-1907341}"
withholders_per_branch="${WITHHOLDERS_PER_BRANCH:-1}"
expect_complete="${EXPECT_COMPLETE:-0}"

printf 'scenario,protocol_version,architecture,fault_profile,repeat,nodes,quorum_size,targets_per_command,latency_profile,withholders_per_branch,actual_status,stdout,stderr,seed,latency_seed\n' > "$manifest"

cargo build --release --features "$features" --bin blossom-subset-gossip-bench

latency_args() {
  local profile="$1"
  case "$profile" in
    even150)
      echo "--latency-distribution even --latency-ms 150"
      ;;
    even25)
      echo "--latency-distribution even --latency-ms 25"
      ;;
    random1_300)
      echo "--latency-distribution random --latency-min-ms 1 --latency-max-ms 300"
      ;;
    random10_600)
      echo "--latency-distribution random --latency-min-ms 10 --latency-max-ms 600"
      ;;
    *)
      echo "unknown latency profile: $profile" >&2
      return 2
      ;;
  esac
}

fault_args() {
  local profile="$1"
  case "$profile" in
    clean)
      echo ""
      ;;
    round0_drop)
      echo "--drop-round0-dispatch"
      ;;
    prefill_withhold)
      echo "--prefill-byzantine-withholders-per-branch $withholders_per_branch"
      ;;
    round0_drop_prefill_withhold)
      echo "--drop-round0-dispatch --prefill-byzantine-withholders-per-branch $withholders_per_branch"
      ;;
    *)
      echo "unknown fault profile: $profile" >&2
      return 2
      ;;
  esac
}

run_case() {
  local protocol_version="$1"
  local architecture="$2"
  local fault_profile="$3"
  local repeat="$4"
  local nodes="$5"
  local quorum_size="$6"
  local targets="$7"
  local latency_profile="$8"

  local trusted_arg=()
  if [[ "$architecture" == "trusted" ]]; then
    trusted_arg=(--trusted)
  fi
  local expect_arg=()
  if [[ "$expect_complete" == "1" ]]; then
    expect_arg=(--expect-complete)
  fi

  local fault_extra
  fault_extra="$(fault_args "$fault_profile")"
  local latency_extra
  latency_extra="$(latency_args "$latency_profile")"
  local withholders=0
  if [[ "$fault_profile" == "prefill_withhold" || "$fault_profile" == "round0_drop_prefill_withhold" ]]; then
    withholders="$withholders_per_branch"
  fi

  local seed=$((seed_base + repeat * 1000003 + nodes * 9176 + quorum_size * 769 + targets * 131 + withholders * 19))
  local latency_seed=$((latency_seed_base + repeat * 65537 + nodes * 4099 + quorum_size * 769 + targets * 257))
  local scenario="head_to_head_${fault_profile}_${architecture}_${latency_profile}_n${nodes}_q${quorum_size}_t${targets}_r${repeat}"
  local label="${scenario}_${protocol_version}"
  local stdout="$out_dir/${label}.stdout"
  local stderr="$out_dir/${label}.stderr"

  set +e
  # shellcheck disable=SC2086
  target/release/blossom-subset-gossip-bench \
    --scenario "$scenario" \
    --protocol-version "$protocol_version" \
    --repeat "$repeat" \
    --nodes "$nodes" \
    --quorum-size "$quorum_size" \
    --epoch-depth "$epochs" \
    --commands-per-node "$commands_per_node" \
    --command-bytes "$command_bytes" \
    --targets-per-command "$targets" \
    --seed "$seed" \
    --latency-seed "$latency_seed" \
    --csv "$csv" \
    --append \
    ${trusted_arg[@]+"${trusted_arg[@]}"} \
    ${expect_arg[@]+"${expect_arg[@]}"} \
    $fault_extra \
    $latency_extra > "$stdout" 2> "$stderr"
  local status=$?
  set -e

  local actual_status="pass"
  if [[ "$status" -ne 0 ]]; then
    actual_status="fail"
  fi

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$scenario" "$protocol_version" "$architecture" "$fault_profile" "$repeat" "$nodes" \
    "$quorum_size" "$targets" "$latency_profile" "$withholders" "$actual_status" \
    "$stdout" "$stderr" "$seed" "$latency_seed" >> "$manifest"

  if [[ "$actual_status" != "pass" ]]; then
    echo "$label failed; see $stderr" >&2
    return 1
  fi
}

for repeat in $(seq 1 "$repeat_runs"); do
  for architecture in ${ARCHITECTURES:-verified}; do
    for nodes in ${NODES:-36 64 72}; do
      quorum_sizes="${BLOSSOM_QUORUM_SIZES:-${QUORUM_SIZES:-6}}"
      for quorum_size in $quorum_sizes; do
        for targets in ${TARGETS_PER_COMMAND:-3 6}; do
          for latency_profile in ${LATENCY_PROFILES:-even150 random1_300}; do
            for fault_profile in ${FAULT_PROFILES:-clean round0_drop prefill_withhold}; do
              for protocol_version in v1 v2; do
                run_case "$protocol_version" "$architecture" "$fault_profile" "$repeat" \
                  "$nodes" "$quorum_size" "$targets" "$latency_profile"
              done
            done
          done
        done
      done
    done
  done
done

python3 "$here/analyze-subset-gossip.py" "$out_dir"

echo "wrote $out_dir"
