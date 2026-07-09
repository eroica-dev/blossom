#!/usr/bin/env bash
# Run the hermetic socket-free Blossom simulator.
#
# Environment:
#   NODES=6
#   REQUESTS=100
#   PAYLOAD_BYTES=0
#   DATA_PATTERN=splitmix
#   DEFAULT_LATENCY_MS=0
#   JITTER_MS=0
#   DROP_PPM=0
#   SIM_SEED=8315169841048547121
#   TRUSTED=0
#   SLOW_NODES=2,3
#   SLOW_AT_MS=0
#   SLOW_LATENCY_MS=50
#   DOWN_NODES=4
#   DOWN_AT_MS=10
#   UP_AT_MS=60
#   RESTART_AFTER_MS=50
#   BUG_LATENCY_BUDGET_MS=100

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"
# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

mkdir -p "$root/results"
summary="$root/results/sim_hermetic_$(timestamp).csv"
events="${summary%.csv}_events.csv"
bugs="${summary%.csv}_bugs.md"

trusted_arg=()
if [[ "${TRUSTED:-0}" == "1" || "${TRUSTED:-false}" == "true" ]]; then
  trusted_arg=(--trusted)
fi

slow_nodes_arg=()
if [[ -n "${SLOW_NODES:-}" ]]; then
  slow_nodes_arg=(--slow-nodes "$SLOW_NODES" --slow-at-ms "${SLOW_AT_MS:-0}" --slow-latency-ms "${SLOW_LATENCY_MS:-50}")
fi

down_nodes_arg=()
if [[ -n "${DOWN_NODES:-}" ]]; then
  down_nodes_arg=(--down-nodes "$DOWN_NODES" --down-at-ms "${DOWN_AT_MS:-10}")
  if [[ -n "${UP_AT_MS:-}" ]]; then
    down_nodes_arg+=(--up-at-ms "$UP_AT_MS")
  elif [[ -n "${RESTART_AFTER_MS:-}" ]]; then
    down_nodes_arg+=(--restart-after-ms "$RESTART_AFTER_MS")
  fi
fi

bug_arg=()
if [[ -n "${BUG_LATENCY_BUDGET_MS:-}" ]]; then
  bug_arg=(--bug-latency-budget-ms "$BUG_LATENCY_BUDGET_MS")
fi

pinned_exec cargo run --release -p blossom-sim --bin blossom-sim-hermetic -- \
  --nodes "${NODES:-6}" \
  --requests "${REQUESTS:-100}" \
  --payload-bytes "${PAYLOAD_BYTES:-0}" \
  --data-pattern "${DATA_PATTERN:-splitmix}" \
  --default-latency-ms "${DEFAULT_LATENCY_MS:-0}" \
  --jitter-ms "${JITTER_MS:-0}" \
  --drop-ppm "${DROP_PPM:-0}" \
  --seed "${SIM_SEED:-8315169841048547121}" \
  ${trusted_arg[@]+"${trusted_arg[@]}"} \
  ${slow_nodes_arg[@]+"${slow_nodes_arg[@]}"} \
  ${down_nodes_arg[@]+"${down_nodes_arg[@]}"} \
  ${bug_arg[@]+"${bug_arg[@]}"} \
  --csv "$summary" \
  --event-log "$events" \
  --bug-log "$bugs"

echo "wrote $summary"
echo "wrote $events"
echo "wrote $bugs"
