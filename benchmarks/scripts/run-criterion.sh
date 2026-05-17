#!/usr/bin/env bash
# Run Criterion microbenchmarks for protocol primitives and runtime operations.
#
# CRITERION_ARGS="primitives" filters the Criterion benchmark set.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"
# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

args=()
if [[ -n "${CRITERION_ARGS:-}" ]]; then
  # shellcheck disable=SC2206
  args=(${CRITERION_ARGS})
fi

if [[ "${#args[@]}" -gt 0 ]]; then
  pinned_exec cargo bench --bench protocol -- "${args[@]}"
else
  pinned_exec cargo bench --bench protocol
fi
