#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${HA_VALIDATION_OUT_DIR:-$ROOT/target/ha-production-validation}"
SOAK_EPOCHS="${BLOSSOM_HA_SOAK_EPOCHS:-1001}"
mkdir -p "$OUT_DIR"

run() {
  local name="$1"
  shift
  echo "==> $name"
  "$@" >"$OUT_DIR/$name.log" 2>&1
  echo "ok: $name"
}

run_tests() {
  local name="$1"
  shift
  run "$name" "$@"
  if ! grep -Eq '^running [1-9][0-9]* tests?$' "$OUT_DIR/$name.log"; then
    echo "error: $name matched no tests" >&2
    exit 1
  fi
}

run ha-clippy \
  cargo clippy -p blossom-consensus --all-targets --features high-availability -- -D warnings

run_tests ha-unit-and-integration \
  cargo test -p blossom-consensus --lib --features high-availability high_availability

run_tests ha-active-active-lifecycle \
  cargo test -p blossom-consensus --lib --features high-availability active_active_ha

run_tests ha-active-active-coordinator \
  cargo test -p blossom-consensus --lib --features high-availability active_active_coordinator

run_tests ha-authenticated-process-restart \
  cargo test -p blossom-consensus --lib --features high-availability \
  high_availability::tests::transport::authenticated_transport_and_durable_state_survive_forced_process_restart

run_tests ha-storage-fault-atomicity \
  cargo test -p blossom-consensus --lib --features high-availability \
  high_availability::tests::durability::durable_acknowledgement_rolls_back

run_tests ha-finalization-fsync-atomicity \
  cargo test -p blossom-consensus --lib --features high-availability \
  high_availability::tests::durability::finalized_epoch_is_not_applied_until_durable_commit_succeeds

run_tests ha-hegel \
  cargo test --jobs 1 -p blossom-consensus --features high-availability \
  --test hegel_high_availability

run_tests ha-durable-soak \
  env BLOSSOM_HA_SOAK_EPOCHS="$SOAK_EPOCHS" \
  cargo test --release -p blossom-consensus --lib --features high-availability \
  high_availability::tests::durability::durable_runtime_survives_thousand_epoch_restart_and_recovery_soak \
  -- --ignored --nocapture

run ha-formal "$ROOT/verification/run-formal.sh"

echo "HA production validation artifacts: $OUT_DIR"
