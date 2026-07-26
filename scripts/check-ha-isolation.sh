#!/usr/bin/env bash
set -euo pipefail

BASE_REF="${1:-origin/main}"

fail() {
  printf 'HA isolation violation: %s\n' "$1" >&2
  exit 1
}

if rg -q 'HighAvailability(Status|Receipt)?|Ha(Message|NodeStatus|WireReceipt)' \
  src/wire.rs src/tcp.rs; then
  fail "HA types leaked into the legacy Blossom wire or TCP profile"
fi

rg -q '^#\[cfg\(feature = "high-availability"\)\]$' src/lib.rs \
  || fail "the HA module is not feature gated"
rg -q '^pub enum HaWireRequest \{' src/high_availability.rs \
  || fail "the isolated HA request envelope is missing"
rg -q '^pub enum HaWireResponse \{' src/high_availability.rs \
  || fail "the isolated HA response envelope is missing"
rg -q '^high-availability = \["dep:hmac"\]$' Cargo.toml \
  || fail "the HA feature dependency boundary changed"

printf 'HA wire and feature isolation passed (comparison base: %s)\n' "$BASE_REF"
