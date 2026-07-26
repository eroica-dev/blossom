#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
FRAMEWORK_ROOT="${DETERMINISTIC_SIM_ROOT:-/home/dtietjen/deterministic-simulation}"
PROFILE="${1:-"$ROOT/simulation/profiles/blossom-protocol-pr.json"}"

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'The deterministic-simulation admission contract is Linux-only.\n' >&2
  exit 2
fi
if [[ ! -x "$FRAMEWORK_ROOT/scripts/sandbox/preflight.sh" ]]; then
  printf 'deterministic-simulation checkout is missing: %s\n' "$FRAMEWORK_ROOT" >&2
  exit 2
fi

"$FRAMEWORK_ROOT/scripts/sandbox/preflight.sh" \
  --profile "$PROFILE" \
  --adapter "$ROOT/scripts/deterministic-framework-adapter.sh" \
  --adapter-timeout-seconds 900 \
  --audit-root "$ROOT/crates/blossom-sim/src/deterministic.rs"
