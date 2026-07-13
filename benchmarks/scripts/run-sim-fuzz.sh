#!/usr/bin/env bash
# Run deterministic node I/O fuzzing through the blossom-sim crate.
#
# Environment:
#   NODES=1
#   CASES=256
#   MAX_PAYLOAD_BYTES=4096
#   DATA_PATTERN=splitmix
#   INCLUDE_VALID=1
#   READ_TIMEOUT_MS=100
#   FUZZ_SEED=7381241417591225393

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"
# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

mkdir -p "$root/results"
out="$root/results/sim_fuzz_$(timestamp).csv"

include_valid_arg=()
if [[ "${INCLUDE_VALID:-1}" == "0" || "${INCLUDE_VALID:-true}" == "false" ]]; then
  include_valid_arg=(--include-valid false)
fi

pinned_exec cargo run --release -p blossom-sim --bin blossom-sim-fuzz -- \
  --nodes "${NODES:-1}" \
  --cases "${CASES:-256}" \
  --max-payload-bytes "${MAX_PAYLOAD_BYTES:-4096}" \
  --data-pattern "${DATA_PATTERN:-splitmix}" \
  --read-timeout-ms "${READ_TIMEOUT_MS:-100}" \
  --seed "${FUZZ_SEED:-7381241417591225393}" \
  --expect-alive \
  ${include_valid_arg[@]+"${include_valid_arg[@]}"} \
  --csv "$out"

echo "wrote $out"
