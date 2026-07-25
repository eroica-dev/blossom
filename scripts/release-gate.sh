#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-"$ROOT/target/release-gate"}"

case "$OUT_DIR" in
  /*) ;;
  *) OUT_DIR="$ROOT/$OUT_DIR" ;;
esac

mkdir -p "$OUT_DIR"

run_step() {
  local name="$1"
  shift
  printf '==> %s\n' "$name"
  (
    cd "$ROOT"
    "$@"
  ) >"$OUT_DIR/$name.log" 2>&1
  printf 'ok: %s\n' "$name"
}

run_step cargo-fmt cargo fmt --all -- --check
run_step cargo-test-workspace cargo test --workspace
run_step cargo-test-all-features cargo test --workspace --all-features
run_step cargo-test-no-default cargo test -p blossom --no-default-features
run_step cargo-test-insecure-fast-hash cargo test -p blossom --features insecure-fast-hash
run_step cargo-clippy cargo clippy --workspace --all-features --all-targets -- -D warnings
run_step ha-production-validation ./scripts/ha-production-validation.sh
run_step formal ./verification/run-formal.sh

printf 'release gate logs: %s\n' "$OUT_DIR"
