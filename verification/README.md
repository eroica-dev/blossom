# Blossom Formal Verification Experiments

This directory contains small, tool-specific proof experiments for the protocol
threshold algorithms. The normal Rust test suite remains the first line of
feedback; these proofs are optional layers that can be run when the matching
toolchain is installed.

To run every available verifier and continue through partial failures:

```sh
./verification/run-formal.sh
```

## Kani

The Kani harnesses live next to the production helpers in `src/algorithm.rs`
under `#[cfg(kani)]`, so they verify the actual code.

```sh
cargo kani --harness supermajority_has_honest_overlap_for_small_validator_sets
cargo kani --harness one_below_supermajority_loses_honest_overlap_for_small_validator_sets
cargo kani --harness supermajority_count_matches_expected_boundary_for_small_validator_sets
```

Current result: all three harnesses verify for symbolic validator counts
`1..=64`.

## Creusot

The Creusot experiment is a standalone crate because Creusot project setup
injects its own `creusot-std` dependency and Why3 configuration.

```sh
cd verification/creusot/thresholds
cargo creusot prove --why3find-arg=-P --why3find-arg=alt-ergo --why3find-arg=-P --why3find-arg=z3
```

Current result: the threshold crate proves when Alt-Ergo and Z3 are selected.
It checks the supermajority arithmetic used by the protocol threshold helpers.

## Verus

The Verus experiment is a standalone Verus source file. It keeps the proof
logic separate from the normal crate because Verus uses its own macro-expanded
Rust subset.

```sh
verus verification/verus/thresholds.rs
```

Current result: crates.io's `verus` package is a placeholder, not the verifier.
Install the real Verus binary/source release before this file can be checked.

## Quint

The Quint model checks the threshold predicates as state invariants over a tiny
constant-state model.

```sh
quint run verification/quint/blossom_thresholds.qnt --invariant=honest_overlap_boundary
quint run verification/quint/blossom_thresholds.qnt --invariant=unsafe_boundary
quint run verification/quint/blossom_thresholds.qnt --invariant=six_node_thresholds
quint verify verification/quint/blossom_thresholds.qnt --invariant=honest_overlap_boundary
quint verify verification/quint/blossom_thresholds.qnt --invariant=unsafe_boundary
```

Current result: `quint run` passes for all three invariants. `quint verify`
passes for the two boundary invariants when Java is available and Apalache can
bind its local checker server port.

## TLA+ / Apalache

The TLA+ spec gives Apalache/TLC the same finite threshold predicates.

```sh
PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH" \
  ~/.quint/apalache-dist-0.56.1/apalache/bin/apalache-mc check \
  --config=verification/tla/BlossomThresholds.cfg \
  --inv=HonestOverlapBoundary \
  verification/tla/BlossomThresholds.tla

PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH" \
  ~/.quint/apalache-dist-0.56.1/apalache/bin/apalache-mc check \
  --config=verification/tla/BlossomThresholds.cfg \
  --inv=UnsafeBoundary \
  verification/tla/BlossomThresholds.tla
```

Current result: direct Apalache checks pass for both TLA+ invariants.
