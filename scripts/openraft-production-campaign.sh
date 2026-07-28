#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${1:-pr}"
OUT_DIR="${BLOSSOM_RAFT_OUT_DIR:-"$ROOT/target/openraft-production/$PROFILE"}"
SEED="${BLOSSOM_RAFT_SEED:-8243311832164208756}"

if [[ -z "${BLOSSOM_RAFT_JOBS:-}" ]]; then
  if command -v nproc >/dev/null 2>&1; then
    DETECTED_JOBS="$(nproc)"
  else
    DETECTED_JOBS="$(sysctl -n hw.logicalcpu 2>/dev/null || printf '4')"
  fi
  if (( DETECTED_JOBS > 8 )); then
    BLOSSOM_RAFT_JOBS=8
  else
    BLOSSOM_RAFT_JOBS="$DETECTED_JOBS"
  fi
fi

case "$PROFILE" in
  pr)
    COMMANDS="${BLOSSOM_RAFT_COMMANDS:-8}"
    NODES="${BLOSSOM_RAFT_NODES:-3}"
    STORAGE="${BLOSSOM_RAFT_STORAGE:-both}"
    FAULTS="${BLOSSOM_RAFT_FAULTS:-none,append-request-loss,append-response-loss,duplicate-append-request,append-request-delay,append-response-delay,vote-request-loss,vote-response-loss}"
    CARGO_MODE=(--profile dev)
    ;;
  nightly)
    COMMANDS="${BLOSSOM_RAFT_COMMANDS:-100}"
    NODES="${BLOSSOM_RAFT_NODES:-2,3,4,5,6,7}"
    STORAGE="${BLOSSOM_RAFT_STORAGE:-both}"
    FAULTS="${BLOSSOM_RAFT_FAULTS:-}"
    CARGO_MODE=(--release)
    ;;
  release)
    COMMANDS="${BLOSSOM_RAFT_COMMANDS:-1001}"
    NODES="${BLOSSOM_RAFT_NODES:-2,3,4,5,6,7}"
    STORAGE="${BLOSSOM_RAFT_STORAGE:-both}"
    FAULTS="${BLOSSOM_RAFT_FAULTS:-}"
    CARGO_MODE=(--release)
    ;;
  *)
    printf 'unknown OpenRaft production profile: %s\n' "$PROFILE" >&2
    exit 2
    ;;
esac

mkdir -p "$OUT_DIR"
COMMAND=(
  cargo run
  "${CARGO_MODE[@]}"
  -p blossom-bench-harness
  --bin blossom-raft-deterministic
  --
  --nodes "$NODES"
  --storage "$STORAGE"
  --commands "$COMMANDS"
  --jobs "$BLOSSOM_RAFT_JOBS"
  --seed "$SEED"
  --output "$OUT_DIR/report.json"
)
if [[ -n "$FAULTS" ]]; then
  COMMAND+=(--fault "$FAULTS")
fi

printf 'OpenRaft production campaign: profile=%s commands=%s nodes=%s storage=%s jobs=%s seed=%s\n' \
  "$PROFILE" "$COMMANDS" "$NODES" "$STORAGE" "$BLOSSOM_RAFT_JOBS" "$SEED"
(
  cd "$ROOT"
  "${COMMAND[@]}"
)
printf 'OpenRaft production artifact: %s\n' "$OUT_DIR/report.json"
