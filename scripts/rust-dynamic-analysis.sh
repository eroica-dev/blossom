#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"
TARGET="${RUST_DYNAMIC_TARGET:-x86_64-unknown-linux-gnu}"

cd "$ROOT"
export CARGO_TARGET_DIR="${RUST_DYNAMIC_TARGET_DIR:-"$ROOT/target/rust-dynamic-$MODE"}"

case "$MODE" in
  miri)
    cargo +nightly miri setup
    for seed in 1 7238271256290328435 1844674407370955161; do
      MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance -Zmiri-symbolic-alignment-check -Zmiri-seed=$seed" \
        cargo +nightly miri test -p blossom-consensus --no-default-features \
          algorithm::tests::configurable_quorums_are_deterministic_and_bounded
      MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance -Zmiri-symbolic-alignment-check -Zmiri-seed=$seed" \
        cargo +nightly miri test -p blossom-consensus --no-default-features \
          --features high-availability \
          high_availability::tests::fixed_array_order_is_hash_sorted_and_deterministic
      MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance -Zmiri-symbolic-alignment-check -Zmiri-seed=$seed" \
        cargo +nightly miri test -p blossom-consensus --no-default-features \
          --features high-availability \
          high_availability::tests::acknowledgement_masks_are_monotonic
    done
    ;;
  asan)
    ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:strict_string_checks=1" \
      RUSTFLAGS="-Zsanitizer=address" \
      RUSTDOCFLAGS="-Zsanitizer=address" \
      cargo +nightly test -p blossom-consensus --target "$TARGET" \
        --no-default-features --features high-availability \
        high_availability::tests::authenticated_ha_process_worker
    ;;
  tsan)
    TSAN_OPTIONS="halt_on_error=1:history_size=7" \
      RUSTFLAGS="-Zsanitizer=thread" \
      RUSTDOCFLAGS="-Zsanitizer=thread" \
      cargo +nightly -Zbuild-std test \
        -p blossom-consensus --target "$TARGET" \
        --no-default-features --features high-availability \
        high_availability::tests::ha_transport_binds_protocol_sender_to_authenticated_peer
    TSAN_OPTIONS="halt_on_error=1:history_size=7" \
      RUSTFLAGS="-Zsanitizer=thread" \
      RUSTDOCFLAGS="-Zsanitizer=thread" \
      cargo +nightly -Zbuild-std test \
        -p blossom-bench-harness --target "$TARGET" \
        raft_adapter::tests::openraft_re_elects_after_current_leader_is_paused
    ;;
  *)
    echo "usage: $0 {miri|asan|tsan}" >&2
    exit 2
    ;;
esac
