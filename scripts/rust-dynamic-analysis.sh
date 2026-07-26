#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"
TARGET="${RUST_DYNAMIC_TARGET:-x86_64-unknown-linux-gnu}"

cd "$ROOT"
export CARGO_TARGET_DIR="${RUST_DYNAMIC_TARGET_DIR:-"$ROOT/target/rust-dynamic-$MODE"}"

cargo_source_overrides=()
if [[ -n "${DETERMINISTIC_SIM_ROOT:-}" ]]; then
  FRAMEWORK_ROOT="$(cd -- "$DETERMINISTIC_SIM_ROOT" && pwd)"
  CORE_CRATE="$FRAMEWORK_ROOT/crates/deterministic-sim-core"
  ENGINE_CRATE="$FRAMEWORK_ROOT/crates/deterministic-sim-engine"
  if [[ ! -f "$CORE_CRATE/Cargo.toml" || ! -f "$ENGINE_CRATE/Cargo.toml" ]]; then
    printf 'deterministic-simulation source override is incomplete: %s\n' \
      "$FRAMEWORK_ROOT" >&2
    exit 2
  fi
  cargo_source_overrides+=(
    --config
    "patch.\"https://github.com/eden-dev-inc/deterministic-simulation.git\".deterministic-sim-core.path=\"$CORE_CRATE\""
    --config
    "patch.\"https://github.com/eden-dev-inc/deterministic-simulation.git\".deterministic-sim-engine.path=\"$ENGINE_CRATE\""
  )
fi

case "$MODE" in
  miri)
    cargo +nightly "${cargo_source_overrides[@]}" miri setup
    for seed in 1 7238271256290328435 1844674407370955161; do
      MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance -Zmiri-symbolic-alignment-check -Zmiri-seed=$seed" \
        cargo +nightly "${cargo_source_overrides[@]}" miri test -p blossom --no-default-features \
          algorithm::tests::configurable_quorums_are_deterministic_and_bounded
      MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance -Zmiri-symbolic-alignment-check -Zmiri-seed=$seed" \
        cargo +nightly "${cargo_source_overrides[@]}" miri test -p blossom --no-default-features \
          --features high-availability \
          high_availability::tests::fixed_array_order_is_hash_sorted_and_deterministic
      MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance -Zmiri-symbolic-alignment-check -Zmiri-seed=$seed" \
        cargo +nightly "${cargo_source_overrides[@]}" miri test -p blossom --no-default-features \
          --features high-availability \
          high_availability::tests::acknowledgement_masks_are_monotonic
    done
    ;;
  asan)
    ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:strict_string_checks=1" \
      RUSTFLAGS="-Zsanitizer=address" \
      RUSTDOCFLAGS="-Zsanitizer=address" \
      cargo +nightly "${cargo_source_overrides[@]}" test -p blossom --target "$TARGET" \
        --no-default-features --features high-availability \
        high_availability::tests::authenticated_ha_process_worker
    ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:strict_string_checks=1" \
      RUSTFLAGS="-Zsanitizer=address" \
      RUSTDOCFLAGS="-Zsanitizer=address" \
      cargo +nightly "${cargo_source_overrides[@]}" test -p blossom-sim --target "$TARGET" \
        --features parallel-networks \
        deterministic::tests::every_deterministic_fault_class_recovers_without_safety_loss
    ;;
  tsan)
    TSAN_OPTIONS="halt_on_error=1:history_size=7" \
      RUSTFLAGS="-Zsanitizer=thread" \
      RUSTDOCFLAGS="-Zsanitizer=thread" \
      cargo +nightly "${cargo_source_overrides[@]}" -Zbuild-std test \
        -p blossom --target "$TARGET" \
        --no-default-features --features high-availability \
        high_availability::tests::ha_transport_binds_protocol_sender_to_authenticated_peer
    TSAN_OPTIONS="halt_on_error=1:history_size=7" \
      RUSTFLAGS="-Zsanitizer=thread" \
      RUSTDOCFLAGS="-Zsanitizer=thread" \
      cargo +nightly "${cargo_source_overrides[@]}" -Zbuild-std test \
        -p blossom-bench-harness --target "$TARGET" \
        raft_adapter::tests::openraft_re_elects_after_current_leader_is_paused
    ;;
  *)
    echo "usage: $0 {miri|asan|tsan}" >&2
    exit 2
    ;;
esac
