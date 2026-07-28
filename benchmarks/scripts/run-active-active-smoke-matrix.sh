#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"

OUTPUT="${ACTIVE_ACTIVE_SMOKE_DIR:-benchmarks/results/active-active-smoke}"
ITERATIONS="${ITERATIONS:-3}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-256}"
MODE="${MODE:-equal-fault}"
mkdir -p "$OUTPUT"

run_cell() {
  quorum_size="$1"
  blossom_nodes="$2"
  raft_voters="$3"
  raft_learners=$((blossom_nodes - raft_voters))
  BLOSSOM_QUORUM_SIZE="$quorum_size" cargo run -p blossom-bench-harness \
    --bin blossom-benchmark-smoke -- \
    --blossom-nodes "$blossom_nodes" \
    --raft-voters "$raft_voters" \
    --raft-learners "$raft_learners" \
    --iterations "$ITERATIONS" \
    --payload-bytes "$PAYLOAD_BYTES" \
    --output "$OUTPUT/q${quorum_size}-n${blossom_nodes}-raft${raft_voters}.json"
}

case "$MODE" in
  equal-fault)
    run_cell 3 3 3
    run_cell 6 6 5
    run_cell 9 9 7
    ;;
  equal-footprint)
    quorum_size="${BLOSSOM_QUORUM_SIZE:-6}"
    run_cell "$quorum_size" 6 3
    run_cell "$quorum_size" 12 5
    run_cell "$quorum_size" 24 5
    run_cell "$quorum_size" 36 7
    run_cell "$quorum_size" 72 7
    ;;
  *)
    echo "MODE must be equal-fault or equal-footprint" >&2
    exit 2
    ;;
esac

echo "active-active smoke artifacts: $OUTPUT"
