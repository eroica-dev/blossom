#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
FRAMEWORK_ROOT="${DETERMINISTIC_SIM_ROOT:-/home/dtietjen/deterministic-simulation}"
MODE="${1:-kvm}"

case "$MODE" in
  kvm)
    SPEC="$ROOT/simulation/vm/blossom-kvm.json"
    PREFLIGHT_MODE=kvm
    ;;
  tcg)
    SPEC="$ROOT/simulation/vm/blossom-tcg-record.json"
    PREFLIGHT_MODE=tcg
    ;;
  *)
    printf 'mode must be kvm or tcg\n' >&2
    exit 2
    ;;
esac

"$FRAMEWORK_ROOT/scripts/vm/preflight.sh" --mode "$PREFLIGHT_MODE"
"$FRAMEWORK_ROOT/scripts/vm/run-product.sh" \
  --spec "$SPEC" \
  --sandbox-id "blossom-ha-$MODE" \
  --exercise "$ROOT/simulation/vm/exercise-blossom-kvm.sh" \
  --run-root "$ROOT/target/deterministic-sandbox/vm-$MODE"
