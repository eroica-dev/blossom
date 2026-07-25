#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"

ITERATIONS="${ITERATIONS:-12}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-256}"
OUTPUT_ROOT="${HA_HEAD_TO_HEAD_FULL_OUTPUT:-benchmarks/results/ha-head-to-head}"
WAIT_FOR_SEAL="${WAIT_FOR_SEAL:-1}"

ITERATIONS="$ITERATIONS" \
PAYLOAD_BYTES="$PAYLOAD_BYTES" \
WAIT_FOR_SEAL="$WAIT_FOR_SEAL" \
HA_HEAD_TO_HEAD_OUTPUT="$OUTPUT_ROOT/full-in-memory.json" \
./benchmarks/scripts/run-ha-head-to-head.sh

ITERATIONS="$ITERATIONS" \
PAYLOAD_BYTES="$PAYLOAD_BYTES" \
WAIT_FOR_SEAL="$WAIT_FOR_SEAL" \
DURABLE=1 \
HA_HEAD_TO_HEAD_OUTPUT="$OUTPUT_ROOT/full-durable.json" \
./benchmarks/scripts/run-ha-head-to-head.sh

echo "Full HA head-to-head artifacts:"
echo "  $OUTPUT_ROOT/full-in-memory.json"
echo "  $OUTPUT_ROOT/full-durable.json"
