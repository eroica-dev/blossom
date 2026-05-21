#!/usr/bin/env bash
# Run the TCP chaos harness benchmark and write a timestamped CSV.
#
# Environment:
#   NODES=6
#   REQUESTS=1000
#   PAYLOAD_BYTES=0
#   DATA_PATTERN=splitmix
#   ITERATIONS=1
#   WARMUP=0
#   LATENCY_MS=0
#   JITTER_MS=0
#   DROP_PPM=0
#   CONNECT_CRASH_PPM=0
#   RESPONSE_CRASH_PPM=0
#   CHAOS_SEED=7089336938131516721
#   TRUSTED=0

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"
# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

mkdir -p "$root/results"
out="$root/results/chaos_$(timestamp).csv"

trusted_arg=()
if [[ "${TRUSTED:-0}" == "1" || "${TRUSTED:-false}" == "true" ]]; then
  trusted_arg=(--trusted)
fi

pinned_exec cargo run --release -p blossom-sim --bin blossom-sim-chaos -- \
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
  ${trusted_arg[@]+"${trusted_arg[@]}"} \
  --csv "$out"

echo "wrote $out"
