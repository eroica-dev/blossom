#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
FRAMEWORK_ROOT="${DETERMINISTIC_SIM_ROOT:-/home/dtietjen/deterministic-simulation}"
PROFILE_NAME="${1:-pr}"
SEEDS="${BLOSSOM_SIMULATION_SEEDS:-1}"

case "$PROFILE_NAME" in
  pr|nightly|release) ;;
  *)
    printf 'profile must be pr, nightly, or release\n' >&2
    exit 2
    ;;
esac
PROFILE="$ROOT/simulation/profiles/blossom-protocol-$PROFILE_NAME.json"

"$ROOT/scripts/deterministic-framework-preflight.sh" "$PROFILE"
"$FRAMEWORK_ROOT/scripts/sandbox/run-campaign.sh" \
  --profile "$PROFILE" \
  --adapter "$ROOT/scripts/deterministic-framework-adapter.sh" \
  --adapter-timeout-seconds 43200 \
  --seeds "$SEEDS" \
  --run-name "blossom-$PROFILE_NAME"
