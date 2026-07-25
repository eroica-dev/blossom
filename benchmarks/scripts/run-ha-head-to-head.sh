#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"

ITERATIONS="${ITERATIONS:-3}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-256}"
OUTPUT="${HA_HEAD_TO_HEAD_OUTPUT:-benchmarks/results/ha-head-to-head/result.json}"
SEAL_ARG=""
DURABLE_ARG=""
if [ "${WAIT_FOR_SEAL:-0}" = "1" ]; then
  SEAL_ARG="--wait-for-seal"
fi
if [ "${DURABLE:-0}" = "1" ]; then
  DURABLE_ARG="--durable"
fi

cargo run --release -p blossom-bench-harness --bin blossom-ha-head-to-head -- \
  --iterations "$ITERATIONS" \
  --payload-bytes "$PAYLOAD_BYTES" \
  --output "$OUTPUT" \
  $SEAL_ARG \
  $DURABLE_ARG

echo "HA head-to-head artifact: $OUTPUT"
