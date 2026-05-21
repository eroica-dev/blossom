#!/usr/bin/env sh
set -u

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

STATUS=0

run_step() {
  name="$1"
  shift
  echo "==> $name"
  if "$@"; then
    echo "ok: $name"
  else
    echo "fail: $name"
    STATUS=1
  fi
}

if cargo kani --version >/dev/null 2>&1; then
  run_step "kani honest overlap" \
    cargo kani --harness supermajority_has_honest_overlap_for_small_validator_sets
  run_step "kani q-1 unsafe boundary" \
    cargo kani --harness one_below_supermajority_loses_honest_overlap_for_small_validator_sets
  run_step "kani supermajority boundary" \
    cargo kani --harness supermajority_count_matches_expected_boundary_for_small_validator_sets
else
  echo "skip: cargo kani is not installed"
fi

if cargo creusot help >/dev/null 2>&1; then
  run_step "creusot threshold crate" \
    sh -c 'cd verification/creusot/thresholds && cargo creusot prove --why3find-arg=-P --why3find-arg=alt-ergo --why3find-arg=-P --why3find-arg=z3'
else
  echo "skip: cargo creusot is not installed"
fi

if command -v verus >/dev/null 2>&1; then
  if verus --version 2>&1 | grep -qi "placeholder crate"; then
    echo "skip: installed verus is the crates.io placeholder, not the verifier"
  else
    run_step "verus thresholds" verus verification/verus/thresholds.rs
  fi
else
  echo "skip: verus is not installed"
fi

if command -v quint >/dev/null 2>&1; then
  run_step "quint honest overlap" \
    quint run verification/quint/blossom_thresholds.qnt --invariant=honest_overlap_boundary
  run_step "quint q-1 unsafe boundary" \
    quint run verification/quint/blossom_thresholds.qnt --invariant=unsafe_boundary
  run_step "quint q=6 thresholds" \
    quint run verification/quint/blossom_thresholds.qnt --invariant=six_node_thresholds
else
  echo "skip: quint is not installed"
fi

JAVA_BIN="/opt/homebrew/opt/openjdk@17/bin"
APALACHE_BIN="${HOME}/.quint/apalache-dist-0.56.1/apalache/bin/apalache-mc"
if [ -x "$APALACHE_BIN" ]; then
  run_step "apalache honest overlap" \
    env PATH="${JAVA_BIN}:$PATH" "$APALACHE_BIN" check \
      --config=verification/tla/BlossomThresholds.cfg \
      --inv=HonestOverlapBoundary \
      verification/tla/BlossomThresholds.tla
  run_step "apalache q-1 unsafe boundary" \
    env PATH="${JAVA_BIN}:$PATH" "$APALACHE_BIN" check \
      --config=verification/tla/BlossomThresholds.cfg \
      --inv=UnsafeBoundary \
      verification/tla/BlossomThresholds.tla
else
  echo "skip: apalache-mc is not installed or has not been downloaded by Quint"
fi

exit "$STATUS"
