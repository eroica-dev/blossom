# Shared helpers for benchmark scripts. Source-only; not executable on its own.

pinned_exec() {
  if [[ -n "${SERVER_CPUSET:-}" ]] && command -v taskset >/dev/null 2>&1; then
    taskset -c "$SERVER_CPUSET" "$@"
  else
    "$@"
  fi
}

report_pinning() {
  if [[ -n "${SERVER_CPUSET:-}" ]]; then
    if command -v taskset >/dev/null 2>&1; then
      echo "pinning: taskset -c $SERVER_CPUSET"
    else
      echo "pinning: SERVER_CPUSET=$SERVER_CPUSET set but taskset is unavailable; pinning skipped"
    fi
  else
    echo "pinning: none (set SERVER_CPUSET=0-3 to pin benchmark process on Linux)"
  fi
}

timestamp() {
  date +%Y%m%d_%H%M%S
}
