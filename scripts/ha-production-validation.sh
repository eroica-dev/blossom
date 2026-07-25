#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${HA_VALIDATION_OUT_DIR:-$ROOT/target/ha-production-validation}"
EPOCHS="${HA_FAULT_EPOCHS:-1200}"
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
  cargo clippy -p blossom --all-targets --features high-availability -- -D warnings

run ha-simulator-clippy \
  cargo clippy -p blossom-sim --all-targets --features high-availability -- -D warnings

run ha-unit-and-integration \
  cargo test -p blossom --features high-availability high_availability

run ha-authenticated-process-restart \
  cargo test -p blossom --features high-availability \
  high_availability::tests::authenticated_transport_and_durable_state_survive_forced_process_restart

run ha-storage-fault-atomicity \
  cargo test -p blossom --features high-availability \
  high_availability::tests::durable_acknowledgement_rolls_back

run ha-finalization-fsync-atomicity \
  cargo test -p blossom --features high-availability \
  high_availability::tests::finalized_epoch_is_not_applied_until_durable_commit_succeeds

run ha-hegel \
  cargo test -p blossom --features high-availability --test hegel_high_availability

run ha-simulator-tests \
  cargo test -p blossom-sim --features high-availability ha::tests

run ha-durable-soak \
  env BLOSSOM_HA_SOAK_EPOCHS="$SOAK_EPOCHS" \
  cargo test --release -p blossom --features high-availability \
  high_availability::tests::durable_runtime_survives_thousand_epoch_restart_and_recovery_soak \
  -- --ignored --nocapture

run ha-chaos-seed-primary \
  cargo run --release -p blossom-sim --features high-availability \
  --bin blossom-sim-ha-chaos -- \
  --epochs "$EPOCHS" \
  --seed 7521983764746858355 \
  --output "$OUT_DIR/ha-chaos-seed-primary.json"

run ha-chaos-seed-424242 \
  cargo run --release -p blossom-sim --features high-availability \
  --bin blossom-sim-ha-chaos -- \
  --epochs "$EPOCHS" \
  --seed 424242 \
  --output "$OUT_DIR/ha-chaos-seed-424242.json"

run ha-chaos-seed-8675309 \
  cargo run --release -p blossom-sim --features high-availability \
  --bin blossom-sim-ha-chaos -- \
  --epochs "$EPOCHS" \
  --seed 8675309 \
  --output "$OUT_DIR/ha-chaos-seed-8675309.json"

run ha-formal "$ROOT/verification/run-formal.sh"

echo "HA production validation artifacts: $OUT_DIR"
