#!/usr/bin/env bash
# Run the real TCP harness across trust/hash/transport optimization modes.
#
# Environment:
#   MODES="trustless_sha trusted_sha trusted_xxh3 trusted_xxh3_external"
#   NODE_COUNTS="6"
#   TRANSACTION_COUNTS="200000"
#   TX_BYTES_LIST="1024"
#   WRITE_CHUNK_BYTES_LIST="0"       0 leaves BLOSSOM_FRAME_WRITE_CHUNK_BYTES unset
#   ITERATIONS=1
#   WARMUP=0
#   DELIVERY_MODE=first-accepted
#   RUNTIME_FLAVOR=current-thread
#   BLOSSOM_MAX_FRAME_SIZE=1073741824
#   BLOSSOM_MAX_PENDING_RAW_DISPATCH_BYTES=2147483648
#   BLOSSOM_MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER=1073741824

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"
# shellcheck source=_lib.sh
. "$here/_lib.sh"

cd "$ws_root"
report_pinning

mkdir -p "$root/results"
out="$root/results/transport_optimization_matrix_$(timestamp).csv"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

bin="$ws_root/target/release/blossom-harness-bench"
first=1

for mode in ${MODES:-trustless_sha trusted_sha trusted_xxh3 trusted_xxh3_external}; do
  features="availability-gossip"
  hash_algorithm="sha256"
  trusted_arg=()
  external_hash_arg=()

  case "$mode" in
    trustless_sha)
      ;;
    trusted_sha)
      trusted_arg=(--trusted)
      ;;
    trusted_xxh3)
      features="availability-gossip,insecure-fast-hash"
      hash_algorithm="xxh3-128x2"
      trusted_arg=(--trusted)
      ;;
    trusted_xxh3_external)
      features="availability-gossip,insecure-fast-hash,external-transaction-hashes"
      hash_algorithm="xxh3-128x2"
      trusted_arg=(--trusted)
      external_hash_arg=(--external-transaction-hashes)
      ;;
    *)
      echo "unknown mode: $mode" >&2
      exit 2
      ;;
  esac

  cargo build --release --features "$features" --bin blossom-harness-bench

  for nodes in ${NODE_COUNTS:-6}; do
    for txs in ${TRANSACTION_COUNTS:-200000}; do
      for tx_bytes in ${TX_BYTES_LIST:-1024}; do
        for write_chunk_bytes in ${WRITE_CHUNK_BYTES_LIST:-0}; do
          env_args=(
            "BLOSSOM_MAX_FRAME_SIZE=${BLOSSOM_MAX_FRAME_SIZE:-1073741824}"
            "BLOSSOM_MAX_PENDING_RAW_DISPATCH_BYTES=${BLOSSOM_MAX_PENDING_RAW_DISPATCH_BYTES:-2147483648}"
            "BLOSSOM_MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER=${BLOSSOM_MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER:-1073741824}"
            "BLOSSOM_HOT_WIRE_CODEC=${BLOSSOM_HOT_WIRE_CODEC:-1}"
          )
          if [[ "$write_chunk_bytes" != "0" ]]; then
            env_args+=("BLOSSOM_FRAME_WRITE_CHUNK_BYTES=$write_chunk_bytes")
          fi

          echo "running mode=$mode nodes=$nodes txs=$txs tx_bytes=$tx_bytes write_chunk_bytes=$write_chunk_bytes"
          run_args=(
            "$bin"
            --nodes "$nodes"
            --transactions "$txs"
            --transaction-bytes "$tx_bytes"
            --application-state-bytes "${APP_STATE_BYTES:-0}"
            --iterations "${ITERATIONS:-1}"
            --warmup "${WARMUP:-0}"
            --delivery-mode "${DELIVERY_MODE:-first-accepted}"
            --runtime-flavor "${RUNTIME_FLAVOR:-current-thread}"
            ${trusted_arg[@]+"${trusted_arg[@]}"}
            ${external_hash_arg[@]+"${external_hash_arg[@]}"}
            --csv "$tmp"
          )
          if [[ -n "${SERVER_CPUSET:-}" ]] && command -v taskset >/dev/null 2>&1; then
            env "${env_args[@]}" taskset -c "$SERVER_CPUSET" "${run_args[@]}"
          else
            env "${env_args[@]}" "${run_args[@]}"
          fi

          if [[ "$first" == "1" ]]; then
            header="$(head -n 1 "$tmp")"
            echo "mode,hash_algorithm,write_chunk_bytes,runtime_flavor,$header" > "$out"
            first=0
          fi

          tail -n +2 "$tmp" | while IFS= read -r row; do
            echo "$mode,$hash_algorithm,$write_chunk_bytes,${RUNTIME_FLAVOR:-current-thread},$row" >> "$out"
          done
        done
      done
    done
  done
done

echo "wrote $out"
