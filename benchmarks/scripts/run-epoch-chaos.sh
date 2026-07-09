#!/usr/bin/env bash
# Run deterministic Blossom epoch convergence under TCP-like transport faults.
#
# Environment:
#   NODES=36
#   EPOCHS=4
#   TXS_PER_NODE=16
#   TX_BYTES=32
#   LATENCY_MS=1
#   JITTER_MS=0
#   ROUND_TIMEOUT_MS=0
#   DROP_PPM=0
#   FUZZ_PPM=0
#   SPIKE_PPM=0
#   SPIKE_LATENCY_MS=0
#   REPAIR_ROUNDS=0
#   REPAIR_FANOUT=0
#   REPAIR_QUORUM=0
#   REPAIR_TIMEOUT_MS=500
#   EPOCH_CHAOS_SEED=7308332182487356264
#   TRUSTED=0
#   SHUFFLE=0
#   REQUIRE_RECONCILIATION=0
#   OBSERVER_ADDR=

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"
# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

mkdir -p "$root/results"
summary="$root/results/epoch_chaos_$(timestamp).csv"
epochs="${summary%.csv}_epochs.csv"
stages="${summary%.csv}_stages.csv"
bugs="${summary%.csv}_bugs.md"

trusted_arg=()
if [[ "${TRUSTED:-0}" == "1" || "${TRUSTED:-false}" == "true" ]]; then
  trusted_arg=(--trusted)
fi

shuffle_arg=()
if [[ "${SHUFFLE:-0}" == "1" || "${SHUFFLE:-false}" == "true" ]]; then
  shuffle_arg=(--shuffle)
fi

reconciliation_arg=()
if [[ "${REQUIRE_RECONCILIATION:-0}" == "1" || "${REQUIRE_RECONCILIATION:-false}" == "true" ]]; then
  reconciliation_arg=(--require-reconciliation)
fi

observer_arg=()
if [[ -n "${OBSERVER_ADDR:-}" ]]; then
  observer_arg=(--observer-addr "$OBSERVER_ADDR")
fi

pinned_exec cargo run --release -p blossom-sim --bin blossom-sim-epoch-chaos -- \
  --nodes "${NODES:-36}" \
  --epochs "${EPOCHS:-4}" \
  --transactions-per-node "${TXS_PER_NODE:-16}" \
  --transaction-bytes "${TX_BYTES:-32}" \
  --latency-ms "${LATENCY_MS:-1}" \
  --jitter-ms "${JITTER_MS:-0}" \
  --round-timeout-ms "${ROUND_TIMEOUT_MS:-0}" \
  --drop-ppm "${DROP_PPM:-0}" \
  --fuzz-ppm "${FUZZ_PPM:-0}" \
  --spike-ppm "${SPIKE_PPM:-0}" \
  --spike-latency-ms "${SPIKE_LATENCY_MS:-0}" \
  --repair-rounds "${REPAIR_ROUNDS:-0}" \
  --repair-fanout "${REPAIR_FANOUT:-0}" \
  --repair-quorum "${REPAIR_QUORUM:-0}" \
  --repair-timeout-ms "${REPAIR_TIMEOUT_MS:-500}" \
  --seed "${EPOCH_CHAOS_SEED:-7308332182487356264}" \
  ${trusted_arg[@]+"${trusted_arg[@]}"} \
  ${shuffle_arg[@]+"${shuffle_arg[@]}"} \
  ${reconciliation_arg[@]+"${reconciliation_arg[@]}"} \
  ${observer_arg[@]+"${observer_arg[@]}"} \
  --csv "$summary" \
  --epoch-log "$epochs" \
  --stage-log "$stages" \
  --bug-log "$bugs"

echo "wrote $summary"
echo "wrote $epochs"
echo "wrote $stages"
echo "wrote $bugs"
