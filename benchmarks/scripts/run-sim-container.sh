#!/usr/bin/env bash
# Build and run the Blossom simulation tools in a VM-like container boundary, with a native
# hermetic fallback for machines where Docker is unavailable.
#
# The Docker backend disables external networking, runs with a read-only root
# filesystem, drops Linux capabilities, and mounts only benchmark results as
# writable state. The native backend is not an OS container, but `sim` is still
# hermetic because it does not open sockets or use wall-clock sleeps.
#
# Usage:
#   ./benchmarks/scripts/run-sim-container.sh sim
#   MODE=chaos REQUESTS=1000 LATENCY_MS=5 ./benchmarks/scripts/run-sim-container.sh
#   SIM_BACKEND=native REQUESTS=100 ./benchmarks/scripts/run-sim-container.sh sim
#   DRY_RUN=1 ./benchmarks/scripts/run-sim-container.sh fuzz
#
# Environment:
#   MODE=sim|chaos|epoch-chaos|fuzz|all
#   SIM_BACKEND=auto|docker|native
#   ALLOW_NATIVE_TCP=0
#   BLOSSOM_SIM_IMAGE=blossom-sim:local
#   BLOSSOM_SIM_FEATURES=filtered-transactions,insecure-fast-hash
#   BUILD=1
#   PULL=0
#   RUNTIME_NETWORK=none
#   MEMORY=4g
#   CPUS=4
#   SERVER_CPUSET=0-3
#   DRY_RUN=0

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
ws_root="$(cd "$root/.." && pwd)"

if [[ $# -gt 0 ]]; then
  mode="$1"
  shift
else
  mode="${MODE:-sim}"
fi

image="${BLOSSOM_SIM_IMAGE:-blossom-sim:local}"
containerfile="${BLOSSOM_SIM_CONTAINERFILE:-$ws_root/crates/blossom-sim/container/Dockerfile}"
runtime_network="${RUNTIME_NETWORK:-none}"
backend="${SIM_BACKEND:-auto}"

mkdir -p "$root/results"

print_cmd() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
}

run_cmd() {
  if [[ "${DRY_RUN:-0}" == "1" || "${DRY_RUN:-false}" == "true" ]]; then
    print_cmd "$@"
  else
    "$@"
  fi
}

docker_available() {
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

append_docker_env_if_set() {
  local name="$1"
  if [[ -n "${!name+x}" ]]; then
    docker_args+=(-e "$name=${!name}")
  fi
}

run_docker_backend() {
  local build_args=(
    docker build
    -f "$containerfile"
    -t "$image"
  )
  if [[ "${PULL:-0}" == "1" || "${PULL:-false}" == "true" ]]; then
    build_args+=(--pull)
  fi
  if [[ -n "${BLOSSOM_SIM_FEATURES:-}" ]]; then
    build_args+=(--build-arg "BLOSSOM_SIM_FEATURES=$BLOSSOM_SIM_FEATURES")
  fi
  build_args+=("$ws_root")

  if [[ "${BUILD:-1}" == "1" || "${BUILD:-true}" == "true" ]]; then
    run_cmd "${build_args[@]}"
  fi

  local docker_args=(
    docker run --rm
    --network "$runtime_network"
    --read-only
    --cap-drop ALL
    --security-opt no-new-privileges
    --tmpfs /tmp:rw,nosuid,nodev,size=64m
    --mount "type=bind,src=$root/results,dst=/workspace/benchmarks/results"
  )

  if [[ -n "${MEMORY:-}" ]]; then
    docker_args+=(--memory "$MEMORY")
  fi
  if [[ -n "${CPUS:-}" ]]; then
    docker_args+=(--cpus "$CPUS")
  fi
  if [[ -n "${SERVER_CPUSET:-}" ]]; then
    docker_args+=(--cpuset-cpus "$SERVER_CPUSET")
  fi

  for name in \
    NODES REQUESTS PAYLOAD_BYTES DATA_PATTERN ITERATIONS WARMUP TRUSTED \
    LATENCY_MS JITTER_MS DROP_PPM CONNECT_CRASH_PPM RESPONSE_CRASH_PPM CHAOS_SEED \
    EPOCHS TXS_PER_NODE TX_BYTES ROUND_TIMEOUT_MS FUZZ_PPM SPIKE_PPM SPIKE_LATENCY_MS REPAIR_ROUNDS REPAIR_FANOUT REPAIR_QUORUM REPAIR_TIMEOUT_MS EPOCH_CHAOS_SEED SHUFFLE \
    CASES MAX_PAYLOAD_BYTES INCLUDE_VALID READ_TIMEOUT_MS FUZZ_SEED EXPECT_ALIVE \
    DEFAULT_LATENCY_MS SIM_SEED SLOW_NODES SLOW_AT_MS SLOW_LATENCY_MS DOWN_NODES DOWN_AT_MS UP_AT_MS RESTART_AFTER_MS BUG_LATENCY_BUDGET_MS \
    BLOSSOM_MAX_FRAME_SIZE BLOSSOM_HOT_WIRE_CODEC BLOSSOM_MAX_PENDING_RAW_DISPATCH_BYTES BLOSSOM_MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER \
    RUST_LOG RUST_BACKTRACE
  do
    append_docker_env_if_set "$name"
  done

  docker_args+=("$image" "$mode")
  docker_args+=("$@")

  run_cmd "${docker_args[@]}"
}

run_native_tcp_or_fail() {
  local name="$1"
  local script="$2"
  shift 2

  if [[ "${ALLOW_NATIVE_TCP:-0}" == "1" || "${ALLOW_NATIVE_TCP:-false}" == "true" ]]; then
    echo "warning: running $name natively; this is not OS-contained and may open loopback TCP sockets" >&2
    run_cmd "$script" "$@"
    return
  fi

  echo "Docker is unavailable and $name needs the Docker backend for OS-contained TCP I/O." >&2
  echo "Set ALLOW_NATIVE_TCP=1 to run the same simulation natively without OS containment." >&2
  exit 69
}

run_native_backend() {
  case "$mode" in
    sim)
      echo "using native hermetic backend for sim; no sockets or wall-clock sleeps are used" >&2
      run_cmd "$here/run-sim-hermetic.sh" "$@"
      ;;
    chaos)
      run_native_tcp_or_fail chaos "$here/run-chaos.sh" "$@"
      ;;
    epoch-chaos)
      echo "using native deterministic backend for epoch-chaos; transport faults are modeled with logical time" >&2
      run_cmd "$here/run-epoch-chaos.sh" "$@"
      ;;
    fuzz)
      run_native_tcp_or_fail fuzz "$here/run-sim-fuzz.sh" "$@"
      ;;
    all)
      echo "using native hermetic backend for sim; no sockets or wall-clock sleeps are used" >&2
      run_cmd "$here/run-sim-hermetic.sh" "$@"
      echo "using native deterministic backend for epoch-chaos; transport faults are modeled with logical time" >&2
      run_cmd "$here/run-epoch-chaos.sh"
      if [[ "${ALLOW_NATIVE_TCP:-0}" == "1" || "${ALLOW_NATIVE_TCP:-false}" == "true" ]]; then
        echo "warning: running fuzz and chaos natively; these are not OS-contained and may open loopback TCP sockets" >&2
        run_cmd "$here/run-sim-fuzz.sh"
        run_cmd "$here/run-chaos.sh"
      else
        echo "skipped native fuzz/chaos because Docker is unavailable; set ALLOW_NATIVE_TCP=1 to run them natively" >&2
      fi
      ;;
    *)
      echo "unknown Blossom simulation mode: $mode" >&2
      echo "expected one of: sim, chaos, epoch-chaos, fuzz, all" >&2
      exit 64
      ;;
  esac
}

case "$backend" in
  docker)
    run_docker_backend "$@"
    ;;
  native)
    run_native_backend "$@"
    ;;
  auto)
    if [[ "${DRY_RUN:-0}" == "1" || "${DRY_RUN:-false}" == "true" ]]; then
      run_docker_backend "$@"
    elif docker_available; then
      run_docker_backend "$@"
    else
      echo "Docker is unavailable; falling back to native backend for supported modes" >&2
      run_native_backend "$@"
    fi
    ;;
  *)
    echo "unknown SIM_BACKEND=$backend" >&2
    echo "expected one of: auto, docker, native" >&2
    exit 64
    ;;
esac
