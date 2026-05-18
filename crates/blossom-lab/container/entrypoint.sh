#!/usr/bin/env bash
# Container entrypoint for the Blossom lab tools.
#
# The outer runner starts this image with external networking disabled, a
# read-only root filesystem, dropped capabilities, and a writable results mount.

set -euo pipefail

mode="${1:-${MODE:-sim}}"
if [[ $# -gt 0 ]]; then
  shift
fi

results_dir="${RESULTS_DIR:-/workspace/benchmarks/results}"
mkdir -p "$results_dir"

timestamp() {
  date -u +%Y%m%d_%H%M%S
}

trusted_arg() {
  if [[ "${TRUSTED:-0}" == "1" || "${TRUSTED:-false}" == "true" ]]; then
    printf '%s\n' "--trusted"
  fi
}

run_chaos() {
  local out="$results_dir/chaos_$(timestamp).csv"
  local trusted=()
  if [[ -n "$(trusted_arg)" ]]; then
    trusted=(--trusted)
  fi

  blossom-lab-chaos \
    --nodes "${NODES:-6}" \
    --requests "${REQUESTS:-1000}" \
    --payload-bytes "${PAYLOAD_BYTES:-0}" \
    --data-pattern "${DATA_PATTERN:-splitmix}" \
    --iterations "${ITERATIONS:-1}" \
    --warmup "${WARMUP:-0}" \
    --latency-ms "${LATENCY_MS:-0}" \
    --jitter-ms "${JITTER_MS:-0}" \
    --drop-ppm "${DROP_PPM:-0}" \
    --connect-crash-ppm "${CONNECT_CRASH_PPM:-0}" \
    --response-crash-ppm "${RESPONSE_CRASH_PPM:-0}" \
    --seed "${CHAOS_SEED:-7089336938131516721}" \
    "${trusted[@]}" \
    --csv "$out" \
    "$@"

  echo "wrote $out"
}

run_fuzz() {
  local out="$results_dir/lab_fuzz_$(timestamp).csv"
  local expect_alive=()
  if [[ "${EXPECT_ALIVE:-1}" == "1" || "${EXPECT_ALIVE:-true}" == "true" ]]; then
    expect_alive=(--expect-alive)
  fi

  blossom-lab-fuzz \
    --nodes "${NODES:-1}" \
    --cases "${CASES:-256}" \
    --max-payload-bytes "${MAX_PAYLOAD_BYTES:-4096}" \
    --data-pattern "${DATA_PATTERN:-splitmix}" \
    --include-valid "${INCLUDE_VALID:-true}" \
    --read-timeout-ms "${READ_TIMEOUT_MS:-100}" \
    --seed "${FUZZ_SEED:-7381241417591225393}" \
    "${expect_alive[@]}" \
    --csv "$out" \
    "$@"

  echo "wrote $out"
}

run_sim() {
  local summary="$results_dir/lab_sim_$(timestamp).csv"
  local events="${summary%.csv}_events.csv"
  local bugs="${summary%.csv}_bugs.md"
  local trusted=()
  local slow_nodes=()
  local down_nodes=()
  local bug_arg=()

  if [[ -n "$(trusted_arg)" ]]; then
    trusted=(--trusted)
  fi
  if [[ -n "${SLOW_NODES:-}" ]]; then
    slow_nodes=(--slow-nodes "$SLOW_NODES" --slow-at-ms "${SLOW_AT_MS:-0}" --slow-latency-ms "${SLOW_LATENCY_MS:-50}")
  fi
  if [[ -n "${DOWN_NODES:-}" ]]; then
    down_nodes=(--down-nodes "$DOWN_NODES" --down-at-ms "${DOWN_AT_MS:-10}")
    if [[ -n "${UP_AT_MS:-}" ]]; then
      down_nodes+=(--up-at-ms "$UP_AT_MS")
    elif [[ -n "${RESTART_AFTER_MS:-}" ]]; then
      down_nodes+=(--restart-after-ms "$RESTART_AFTER_MS")
    fi
  fi
  if [[ -n "${BUG_LATENCY_BUDGET_MS:-}" ]]; then
    bug_arg=(--bug-latency-budget-ms "$BUG_LATENCY_BUDGET_MS")
  fi

  blossom-lab-sim \
    --nodes "${NODES:-6}" \
    --requests "${REQUESTS:-100}" \
    --payload-bytes "${PAYLOAD_BYTES:-0}" \
    --data-pattern "${DATA_PATTERN:-splitmix}" \
    --default-latency-ms "${DEFAULT_LATENCY_MS:-0}" \
    --jitter-ms "${JITTER_MS:-0}" \
    --drop-ppm "${DROP_PPM:-0}" \
    --seed "${SIM_SEED:-8315169841048547121}" \
    "${trusted[@]}" \
    "${slow_nodes[@]}" \
    "${down_nodes[@]}" \
    "${bug_arg[@]}" \
    --csv "$summary" \
    --event-log "$events" \
    --bug-log "$bugs" \
    "$@"

  echo "wrote $summary"
  echo "wrote $events"
  echo "wrote $bugs"
}

run_epoch_chaos() {
  local summary="$results_dir/epoch_chaos_$(timestamp).csv"
  local epochs="${summary%.csv}_epochs.csv"
  local bugs="${summary%.csv}_bugs.md"
  local trusted=()
  local shuffle=()

  if [[ -n "$(trusted_arg)" ]]; then
    trusted=(--trusted)
  fi
  if [[ "${SHUFFLE:-0}" == "1" || "${SHUFFLE:-false}" == "true" ]]; then
    shuffle=(--shuffle)
  fi

  blossom-lab-epoch-chaos \
    --nodes "${NODES:-36}" \
    --epochs "${EPOCHS:-4}" \
    --transactions-per-node "${TXS_PER_NODE:-16}" \
    --transaction-bytes "${TX_BYTES:-32}" \
    --latency-ms "${LATENCY_MS:-1}" \
    --jitter-ms "${JITTER_MS:-0}" \
    --round-timeout-ms "${ROUND_TIMEOUT_MS:-50}" \
    --drop-ppm "${DROP_PPM:-0}" \
    --fuzz-ppm "${FUZZ_PPM:-0}" \
    --spike-ppm "${SPIKE_PPM:-0}" \
    --spike-latency-ms "${SPIKE_LATENCY_MS:-0}" \
    --repair-rounds "${REPAIR_ROUNDS:-0}" \
    --repair-fanout "${REPAIR_FANOUT:-0}" \
    --repair-quorum "${REPAIR_QUORUM:-0}" \
    --repair-timeout-ms "${REPAIR_TIMEOUT_MS:-500}" \
    --seed "${EPOCH_CHAOS_SEED:-7308332182487356264}" \
    "${trusted[@]}" \
    "${shuffle[@]}" \
    --csv "$summary" \
    --epoch-log "$epochs" \
    --bug-log "$bugs" \
    "$@"

  echo "wrote $summary"
  echo "wrote $epochs"
  echo "wrote $bugs"
}

case "$mode" in
  chaos)
    run_chaos "$@"
    ;;
  epoch-chaos)
    run_epoch_chaos "$@"
    ;;
  fuzz)
    run_fuzz "$@"
    ;;
  sim)
    run_sim "$@"
    ;;
  all)
    run_sim "$@"
    run_epoch_chaos
    run_fuzz
    run_chaos
    ;;
  *)
    echo "unknown blossom-lab container mode: $mode" >&2
    echo "expected one of: sim, chaos, epoch-chaos, fuzz, all" >&2
    exit 64
    ;;
esac
