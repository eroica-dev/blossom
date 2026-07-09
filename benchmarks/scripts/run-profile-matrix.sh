#!/usr/bin/env bash
# Run deterministic Blossom node profiling scenarios.
#
# This uses the socket-free hermetic environment so network latency, CPU delay,
# CPU stalls, node restarts, and hardware-style faults are replayable by seed.
#
# Environment:
#   TRUST_MODES="verified trusted"
#   NODES_LIST="16 64"
#   REQUESTS=10000
#   PAYLOAD_BYTES=1024
#   LATENCIES="0 25 100"
#   CPU_DELAYS="0 1 5"
#   CPU_NODES=""                   comma-separated; empty means no CPU profile
#   TARGET_NODE=""                 set to isolate a hot node
#   DROP_PPM=0
#   JITTER_MS=0
#   CPU_JITTER_MS=0
#   CPU_STALL_PPM=0
#   HARDWARE_FAULT_NODES=""        comma-separated; empty means no hardware faults
#   HARDWARE_CRASH_PPM=0
#   HARDWARE_IO_ERROR_PPM=0
#   HARDWARE_MEMORY_ERROR_PPM=0
#   SEED=8317631721911771121
#   FEATURES=availability-gossip

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"

cd "$ws_root"

feature_args=()
if [[ -n "${FEATURES:-availability-gossip}" ]]; then
  feature_args=(--features "${FEATURES:-availability-gossip}")
fi

cargo build --release -p blossom-sim --bin blossom-sim-hermetic "${feature_args[@]}"
bin="$ws_root/target/release/blossom-sim-hermetic"

stamp="$(date +%Y%m%d_%H%M%S)"
out_dir="$root/results/profile_matrix_$stamp"
mkdir -p "$out_dir"

echo "output-dir: $out_dir"

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

  for nodes in ${NODES_LIST:-16 64}; do
    for latency in ${LATENCIES:-0 25 100}; do
      for cpu_delay in ${CPU_DELAYS:-0 1 5}; do
        label="trust_${trust_mode}_nodes_${nodes}_lat_${latency}_cpu_${cpu_delay}"
        summary="$out_dir/${label}_summary.csv"
        events="$out_dir/${label}_events.csv"
        perf="$out_dir/${label}_perf.csv"
        profile="$out_dir/${label}_profile.csv"
        bug_log="$out_dir/${label}_bugs.md"

        args=(
          "$bin"
          --nodes "$nodes"
          --requests "${REQUESTS:-10000}"
          --payload-bytes "${PAYLOAD_BYTES:-1024}"
          --default-latency-ms "$latency"
          --jitter-ms "${JITTER_MS:-0}"
          --drop-ppm "${DROP_PPM:-0}"
          --seed "${SEED:-8317631721911771121}"
          --csv "$summary"
          --event-log "$events"
          --perf-csv "$perf"
          --profile-csv "$profile"
          --bug-log "$bug_log"
          ${trusted_arg[@]+"${trusted_arg[@]}"}
        )

        if [[ -n "${TARGET_NODE:-}" ]]; then
          args+=(--target-node "$TARGET_NODE")
        fi

        cpu_nodes="${CPU_NODES:-}"
        if [[ -z "$cpu_nodes" && "$cpu_delay" != "0" ]]; then
          cpu_nodes="${TARGET_NODE:-0}"
        fi
        if [[ -n "$cpu_nodes" ]]; then
          args+=(
            --cpu-nodes "$cpu_nodes"
            --cpu-delay-ms "$cpu_delay"
            --cpu-jitter-ms "${CPU_JITTER_MS:-0}"
            --cpu-stall-ppm "${CPU_STALL_PPM:-0}"
          )
        fi

        if [[ -n "${HARDWARE_FAULT_NODES:-}" ]]; then
          args+=(
            --hardware-fault-nodes "$HARDWARE_FAULT_NODES"
            --hardware-crash-ppm "${HARDWARE_CRASH_PPM:-0}"
            --hardware-io-error-ppm "${HARDWARE_IO_ERROR_PPM:-0}"
            --hardware-memory-error-ppm "${HARDWARE_MEMORY_ERROR_PPM:-0}"
          )
        fi

        echo "running $label"
        "${args[@]}"
      done
    done
  done
done

echo "wrote $out_dir"
