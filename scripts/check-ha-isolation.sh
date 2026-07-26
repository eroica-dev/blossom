#!/usr/bin/env bash
set -euo pipefail

BASE_REF="${1:-origin/main}"

fail() {
  printf 'HA isolation violation: %s\n' "$1" >&2
  exit 1
}

matches() {
  local pattern="$1"
  shift
  if command -v rg >/dev/null 2>&1; then
    rg -q "$pattern" "$@"
  else
    grep -Eq "$pattern" "$@"
  fi
}

if matches 'HighAvailability(Status|Receipt)?|Ha(Message|NodeStatus|WireReceipt)' \
  src/wire.rs src/tcp.rs; then
  fail "HA types leaked into the legacy Blossom wire or TCP profile"
fi

matches '^#\[cfg\(feature = "high-availability"\)\]$' src/lib.rs \
  || fail "the HA module is not feature gated"
matches '^pub enum HaWireRequest \{' src/high_availability.rs \
  || fail "the isolated HA request envelope is missing"
matches '^pub enum HaWireResponse \{' src/high_availability.rs \
  || fail "the isolated HA response envelope is missing"
matches '^high-availability = \["dep:hmac"\]$' Cargo.toml \
  || fail "the HA feature dependency boundary changed"

printf 'HA wire and feature isolation passed (comparison base: %s)\n' "$BASE_REF"
