#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="nightly"
BUDGET="2h"
SEED="7238271256290328435"
OUT_DIR="${DETERMINISTIC_OUT_DIR:-"$ROOT/target/deterministic-sandbox"}"

while (($#)); do
  case "$1" in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --budget)
      BUDGET="$2"
      shift 2
      ;;
    --seed)
      SEED="$2"
      shift 2
      ;;
    --output-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

case "$BUDGET" in
  *h) BUDGET_SECONDS="$(( ${BUDGET%h} * 3600 ))" ;;
  *m) BUDGET_SECONDS="$(( ${BUDGET%m} * 60 ))" ;;
  *s) BUDGET_SECONDS="${BUDGET%s}" ;;
  *) BUDGET_SECONDS="$BUDGET" ;;
esac

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$PROFILE-$SEED"
RUN_DIR="$OUT_DIR/$RUN_ID"
mkdir -p "$RUN_DIR"

run_step() {
  local name="$1"
  shift
  printf '==> %s\n' "$name"
  (
    cd "$ROOT"
    "$@"
  ) >"$RUN_DIR/$name.log" 2>&1
  printf 'ok: %s\n' "$name"
}

run_step all-hegel \
  cargo test -p blossom --all-features \
  --test hegel_active_active \
  --test hegel_high_availability \
  --test hegel_parallel_networks \
  --test hegel_quorum \
  --test hegel_trusted_dag \
  --test hegel_trusted_network

run_step deterministic-campaign \
  cargo run --release -p blossom-sim --features parallel-networks \
  --bin blossom-deterministic-campaign -- \
  --profile "$PROFILE" \
  --seed "$SEED" \
  --budget-seconds "$BUDGET_SECONDS" \
  --output "$RUN_DIR/report.json"

case "$PROFILE" in
  pr) OPENRAFT_COMMANDS=50 ;;
  nightly) OPENRAFT_COMMANDS=1200 ;;
  release) OPENRAFT_COMMANDS=10000 ;;
  *)
    printf 'unsupported deterministic profile: %s\n' "$PROFILE" >&2
    exit 2
    ;;
esac

run_step openraft-deterministic-control \
  cargo run --release -p blossom-bench-harness \
  --bin blossom-raft-deterministic -- \
  --commands "$OPENRAFT_COMMANDS" \
  --seed "$SEED" \
  --output "$RUN_DIR/openraft-report.json"

run_step openraft-durable-soak \
  env BLOSSOM_RAFT_SOAK_COMMANDS=1001 \
  cargo test --release -p blossom-bench-harness \
  raft_adapter::tests::durable_openraft_survives_thousand_write_leader_and_follower_restart_soak \
  -- --ignored --nocapture

run_step trusted-dag-1001-checkpoint-soak \
  cargo test --release -p blossom --features trusted-checkpoint-dag \
  trusted_dag::tests::thousand_and_one_checkpoint_fault_soak_preserves_prefix_and_order \
  -- --nocapture

printf 'deterministic campaign artifacts: %s\n' "$RUN_DIR"
