#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"

QUORUM_SIZE_VALUE="${BLOSSOM_QUORUM_SIZE:-${QUORUM_SIZE:-6}}"
OUTPUT="${ACTIVE_ACTIVE_MANIFEST_DIR:-benchmarks/manifests/active_active}"

cargo test -p blossom-consensus --test hegel_quorum --test hegel_active_active
cargo test -p blossom-bench-harness
cargo run -p blossom-bench-harness --bin blossom-benchmark-matrix -- \
  --quorum-size "$QUORUM_SIZE_VALUE" \
  --output "$OUTPUT"
./verification/run-formal.sh

echo "active-active gates passed; matrix: $OUTPUT/matrix.json"
