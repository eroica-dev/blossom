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

run ha-clippy \
  cargo clippy -p blossom-consensus --all-targets --features high-availability -- -D warnings

run ha-unit-and-integration \
  cargo test -p blossom-consensus --features high-availability high_availability

run ha-authenticated-process-restart \
  cargo test -p blossom-consensus --features high-availability \
  high_availability::tests::authenticated_transport_and_durable_state_survive_forced_process_restart

run ha-storage-fault-atomicity \
  cargo test -p blossom-consensus --features high-availability \
  high_availability::tests::durable_acknowledgement_rolls_back

run ha-finalization-fsync-atomicity \
  cargo test -p blossom-consensus --features high-availability \
  high_availability::tests::finalized_epoch_is_not_applied_until_durable_commit_succeeds

run ha-hegel \
  cargo test -p blossom-consensus --features high-availability --test hegel_high_availability

run ha-durable-soak \
  env BLOSSOM_HA_SOAK_EPOCHS="$SOAK_EPOCHS" \
  cargo test --release -p blossom-consensus --features high-availability \
  high_availability::tests::durable_runtime_survives_thousand_epoch_restart_and_recovery_soak \
  -- --ignored --nocapture

run ha-formal "$ROOT/verification/run-formal.sh"

echo "HA production validation artifacts: $OUT_DIR"
