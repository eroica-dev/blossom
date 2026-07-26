#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FRAMEWORK_ROOT="${DETERMINISTIC_SIM_ROOT:-/home/dtietjen/deterministic-simulation}"
BASE_IMAGE="${BLOSSOM_VM_BASE_IMAGE:-/var/lib/deterministic-sim/images/ubuntu-24.04-amd64.img}"
OUTPUT="${BLOSSOM_VM_IMAGE:-/var/lib/deterministic-sim/images/blossom-ubuntu.qcow2}"

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'Blossom VM images must be built on Linux.\n' >&2
  exit 2
fi
if [[ ! -d "$FRAMEWORK_ROOT" ]]; then
  printf 'deterministic-simulation checkout is missing: %s\n' "$FRAMEWORK_ROOT" >&2
  exit 2
fi
if [[ ! -f "$BASE_IMAGE" ]]; then
  printf 'pinned Ubuntu base image is missing: %s\n' "$BASE_IMAGE" >&2
  exit 2
fi

(
  cd "$FRAMEWORK_ROOT"
  cargo build --release -p deterministic-sim-vm --bin deterministic-sim-guest-agent
)
(
  cd "$ROOT"
  CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release \
    -p blossom-sim \
    --features parallel-networks,observability \
    --bin blossom-deterministic-campaign
)

"$FRAMEWORK_ROOT/scripts/vm/build-ubuntu-guest.sh" \
  --base-image "$BASE_IMAGE" \
  --output "$OUTPUT" \
  --agent "$FRAMEWORK_ROOT/target/release/deterministic-sim-guest-agent" \
  --mkdir /opt/blossom \
  --mkdir /opt/blossom/bin \
  --mkdir /var/lib/blossom-sim \
  --upload "$ROOT/target/release/blossom-deterministic-campaign:/opt/blossom/bin/blossom-deterministic-campaign"
