#!/usr/bin/env bash
set -euo pipefail

BASE_REF="${1:-origin/main}"

allowed_path() {
  case "$1" in
    .github/workflows/ha-merge-gate.yml \
      | Cargo.lock \
      | Cargo.toml \
      | README.md \
      | crates/blossom-sim/Cargo.toml \
      | crates/blossom-sim/src/bin/blossom-sim-ha-chaos.rs \
      | crates/blossom-sim/src/ha.rs \
      | crates/blossom-sim/src/lib.rs \
      | guides/feature-flags.md \
      | guides/high-availability.md \
      | guides/testing-and-validation.md \
      | scripts/check-ha-isolation.sh \
      | scripts/ha-production-validation.sh \
      | scripts/production-validation.sh \
      | scripts/release-gate.sh \
      | src/error.rs \
      | src/high_availability.rs \
      | src/lib.rs \
      | src/wire.rs \
      | tests/hegel_high_availability.rs)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

unexpected=0
while IFS= read -r path; do
  if ! allowed_path "$path"; then
    printf 'HA isolation violation: %s is outside the HA-only allowlist\n' "$path" >&2
    unexpected=1
  fi
done < <(git diff --name-only "$BASE_REF"...HEAD)

if ((unexpected != 0)); then
  exit 1
fi

protected_protocol_files=(
  src/algorithm.rs
  src/hash.rs
  src/harness.rs
  src/overlay.rs
  src/runtime.rs
  src/service_client.rs
  src/state.rs
  src/tcp.rs
  tests/e2e_tcp.rs
)

for path in "${protected_protocol_files[@]}"; do
  if ! git diff --quiet "$BASE_REF"...HEAD -- "$path"; then
    printf 'HA isolation violation: legacy protocol file changed: %s\n' "$path" >&2
    exit 1
  fi
done

printf 'HA isolation check passed against %s\n' "$BASE_REF"
