#!/usr/bin/env bash
# Run one local availability-gossip benchmark and write a timestamped CSV.
#
# Environment:
#   NODES=36
#   ENTRIES=128
#   PAYLOAD_BYTES=4096
#   FANOUT=6
#   TARGETS_PER_ENTRY=6
#   ITERATIONS=5
#   WARMUP=1
#   TRUSTED=0
#   SKIP_FETCH=0
#   SINGLE_FETCH=0
#   DROP_GOSSIP_EVERY=0
#   EXPECT_COMPLETE=0

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"
# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

mkdir -p "$root/results"
out="$root/results/gossip_$(timestamp).csv"

trusted_arg=()
if [[ "${TRUSTED:-0}" == "1" || "${TRUSTED:-false}" == "true" ]]; then
  trusted_arg=(--trusted)
fi

skip_fetch_arg=()
if [[ "${SKIP_FETCH:-0}" == "1" || "${SKIP_FETCH:-false}" == "true" ]]; then
  skip_fetch_arg=(--skip-fetch)
fi

single_fetch_arg=()
if [[ "${SINGLE_FETCH:-0}" == "1" || "${SINGLE_FETCH:-false}" == "true" ]]; then
  single_fetch_arg=(--single-fetch)
fi

drop_gossip_arg=()
if [[ "${DROP_GOSSIP_EVERY:-0}" != "0" ]]; then
  drop_gossip_arg=(--drop-gossip-every "${DROP_GOSSIP_EVERY}")
fi

expect_complete_arg=()
if [[ "${EXPECT_COMPLETE:-0}" == "1" || "${EXPECT_COMPLETE:-false}" == "true" ]]; then
  expect_complete_arg=(--expect-complete)
fi

pinned_exec cargo run --release --features availability-gossip --bin blossom-gossip-bench -- \
  --nodes "${NODES:-36}" \
  --entries "${ENTRIES:-128}" \
  --payload-bytes "${PAYLOAD_BYTES:-4096}" \
  --fanout "${FANOUT:-6}" \
  --targets-per-entry "${TARGETS_PER_ENTRY:-6}" \
  --iterations "${ITERATIONS:-5}" \
  --warmup "${WARMUP:-1}" \
  ${trusted_arg[@]+"${trusted_arg[@]}"} \
  ${skip_fetch_arg[@]+"${skip_fetch_arg[@]}"} \
  ${single_fetch_arg[@]+"${single_fetch_arg[@]}"} \
  ${drop_gossip_arg[@]+"${drop_gossip_arg[@]}"} \
  ${expect_complete_arg[@]+"${expect_complete_arg[@]}"} \
  --csv "$out"

echo "wrote $out"
