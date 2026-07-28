#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

package_args=(--locked)
if [[ "${ALLOW_DIRTY:-0}" == "1" ]]; then
  package_args+=(--allow-dirty)
fi

cargo package "${package_args[@]}" -p blossom-consensus

printf '%s\n' "Blossom release packages prepared; no registry upload was performed."
