#!/usr/bin/env bash
# Run the concurrent TCP chaos benchmark across CPU core counts.
#
# This is intended for a Linux benchmarking host. On Linux it pins the benchmark
# process with taskset so each row is comparable across 1/2/4/8/16/32 cores.
#
# Environment:
#   CORE_COUNTS="1 2 4 8 16 32"
#   TRUST_MODES="verified trusted"    verified=trustless path, trusted=known-safe path
#   NODES=64
#   REQUESTS=100000
#   PAYLOAD_BYTES=1024
#   DATA_PATTERN=splitmix
#   ITERATIONS=3
#   WARMUP=1
#   CONCURRENCY=                    optional fixed concurrency for all runs
#   CONCURRENCY_PER_CORE=32         used when CONCURRENCY is unset
#   LATENCY_MS=0
#   JITTER_MS=0
#   DROP_PPM=0
#   CONNECT_CRASH_PPM=0
#   RESPONSE_CRASH_PPM=0
#   CHAOS_SEED=7089336938131516721
#   FEATURES=availability-gossip
#   PIN_CORES=1                     Linux only; set 0 to skip taskset pinning
#   CPUSET_START=0

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"

cd "$ws_root"

mkdir -p "$root/results"
out="$root/results/node_core_matrix_$(date +%Y%m%d_%H%M%S).csv"
node_out="${out%.csv}_nodes.csv"

feature_args=()
if [[ -n "${FEATURES:-availability-gossip}" ]]; then
  feature_args=(--features "${FEATURES:-availability-gossip}")
fi

cargo build --release -p blossom-sim --bin blossom-sim-chaos "${feature_args[@]}"
bin="$ws_root/target/release/blossom-sim-chaos"

echo "output: $out"
echo "node-output: $node_out"
echo "open-file-limit: $(ulimit -n)"

for trust_mode in ${TRUST_MODES:-verified trusted}; do
  trusted_arg=()
  case "$trust_mode" in
    trusted | true | 1)
      trusted_arg=(--trusted)
      ;;
    verified | trustless | false | 0)
      ;;
    *)
      echo "unknown trust mode: $trust_mode" >&2
      exit 2
      ;;
  esac

  for cores in ${CORE_COUNTS:-1 2 4 8 16 32}; do
    concurrency="${CONCURRENCY:-$((cores * ${CONCURRENCY_PER_CORE:-32}))}"
    cpuset_start="${CPUSET_START:-0}"
    cpuset_end=$((cpuset_start + cores - 1))
    pin_prefix=()

    if [[ "${PIN_CORES:-1}" == "1" && -x "$(command -v taskset || true)" ]]; then
      pin_prefix=(taskset -c "$cpuset_start-$cpuset_end")
      echo "running trust=$trust_mode cores=$cores cpuset=$cpuset_start-$cpuset_end concurrency=$concurrency"
    else
      echo "running trust=$trust_mode cores=$cores unpinned concurrency=$concurrency"
    fi

    run_args=(
      "$bin"
      --nodes "${NODES:-64}"
      --requests "${REQUESTS:-100000}"
      --payload-bytes "${PAYLOAD_BYTES:-1024}"
      --data-pattern "${DATA_PATTERN:-splitmix}"
      --iterations "${ITERATIONS:-3}"
      --concurrency "$concurrency"
      --cpu-cores "$cores"
      --warmup "${WARMUP:-1}"
      --latency-ms "${LATENCY_MS:-0}"
      --jitter-ms "${JITTER_MS:-0}"
      --drop-ppm "${DROP_PPM:-0}"
      --connect-crash-ppm "${CONNECT_CRASH_PPM:-0}"
      --response-crash-ppm "${RESPONSE_CRASH_PPM:-0}"
      --seed "${CHAOS_SEED:-7089336938131516721}"
      ${trusted_arg[@]+"${trusted_arg[@]}"}
      --append
      --csv "$out"
      --node-perf-csv "$node_out"
    )
    if [[ "${#pin_prefix[@]}" -gt 0 ]]; then
      "${pin_prefix[@]}" "${run_args[@]}"
    else
      "${run_args[@]}"
    fi
  done
done

echo "wrote $out"
echo "wrote $node_out"
