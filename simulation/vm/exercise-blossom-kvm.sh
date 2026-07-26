#!/usr/bin/env bash
set -euo pipefail

: "${DSIM_VM_CONTROL:?DSIM_VM_CONTROL is required}"
: "${DSIM_VM_SOCKET:?DSIM_VM_SOCKET is required}"
: "${DSIM_VM_SANDBOX_ID:?DSIM_VM_SANDBOX_ID is required}"

vmctl() {
  "$DSIM_VM_CONTROL" --socket "$DSIM_VM_SOCKET" "$@"
}

sleep 5
vmctl snapshot "$DSIM_VM_SANDBOX_ID" before-faults
vmctl pause "$DSIM_VM_SANDBOX_ID"
vmctl resume "$DSIM_VM_SANDBOX_ID"
vmctl disk-fault "$DSIM_VM_SANDBOX_ID" stall
sleep 5
vmctl disk-fault "$DSIM_VM_SANDBOX_ID" clear
vmctl network-fault "$DSIM_VM_SANDBOX_ID" drop --rate-ppm 10000
sleep 5
vmctl network-fault "$DSIM_VM_SANDBOX_ID" link-up
vmctl restore "$DSIM_VM_SANDBOX_ID" before-faults
sleep 5
vmctl crash-process "$DSIM_VM_SANDBOX_ID"
vmctl status "$DSIM_VM_SANDBOX_ID"
