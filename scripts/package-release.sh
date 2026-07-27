#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

package_args=(--locked)
if [[ "${ALLOW_DIRTY:-0}" == "1" ]]; then
  package_args+=(--allow-dirty)
fi

cargo package "${package_args[@]}" -p blossom-propagation

if [[ "${REGISTRY_DEPS_READY:-0}" == "1" ]]; then
  cargo package "${package_args[@]}" -p blossom-consensus
  cargo package "${package_args[@]}" -p blossom-observer
else
  mkdir -p target/release-package
  cargo package "${package_args[@]}" -p blossom-consensus --list \
    >target/release-package/blossom-consensus-2.0.0.files
  cargo package "${package_args[@]}" -p blossom-observer --list \
    >target/release-package/blossom-observer-2.0.0.files
  printf '%s\n' \
    "Registry-dependent archives deferred until shardlog and blossom-propagation are published."
fi

printf '%s\n' "Blossom packages prepared; no registry upload was performed."
