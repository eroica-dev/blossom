#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-"$ROOT/target"}"
ADAPTER="$TARGET_DIR/release/blossom-deterministic-adapter"
CAMPAIGN="$TARGET_DIR/release/blossom-deterministic-campaign"

(
  cd "$ROOT"
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
  CARGO_NET_GIT_FETCH_WITH_CLI=true cargo "${cargo_source_overrides[@]}" build --release \
    -p blossom-sim \
    --features parallel-networks,observability \
    --bin blossom-deterministic-adapter \
    --bin blossom-deterministic-campaign
)

export BLOSSOM_DETERMINISTIC_CAMPAIGN="$CAMPAIGN"
exec "$ADAPTER"
