#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT"

cargo test -p blossom-consensus --no-default-features --features active-passive \
  --test active_passive_openraft

cargo test -p blossom-bench-harness raft_adapter::tests:: -- --nocapture

"$ROOT/scripts/openraft-production-campaign.sh" "${BLOSSOM_RAFT_PROFILE:-pr}"

BLOSSOM_RAFT_SOAK_COMMANDS=1001 \
  cargo test -p blossom-bench-harness \
  durable_openraft_survives_thousand_write_leader_and_follower_restart_soak \
  -- --ignored
