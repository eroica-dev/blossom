#!/usr/bin/env python3
"""Summarize prefill-dispatch safety-frontier matrix output."""

from __future__ import annotations

import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        return
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def mean(values: list[float]) -> float:
    return statistics.fmean(values) if values else 0.0


def status_rows(manifest: list[dict[str, str]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, int, int, str], list[dict[str, str]]] = defaultdict(list)
    for row in manifest:
        grouped[
            (
                row["architecture"],
                int(row["quorum_size"]),
                int(row["withholders_per_branch"]),
                row["latency_profile"],
            )
        ].append(row)

    output = []
    for (arch, quorum, withholders, latency), rows in sorted(grouped.items()):
        expected_pass = sum(1 for row in rows if row["expected_status"] == "pass")
        expected_fail = sum(1 for row in rows if row["expected_status"] == "fail")
        expected_any = sum(1 for row in rows if row["expected_status"] == "any")
        actual_pass = sum(1 for row in rows if row["actual_status"] == "pass")
        actual_fail = sum(1 for row in rows if row["actual_status"] == "fail")
        mismatches = sum(
            1
            for row in rows
            if row["expected_status"] != "any" and row["expected_status"] != row["actual_status"]
        )
        output.append(
            {
                "architecture": arch,
                "quorum_size": quorum,
                "withholders_per_branch": withholders,
                "latency_profile": latency,
                "cases": len(rows),
                "expected_pass": expected_pass,
                "expected_fail": expected_fail,
                "expected_any": expected_any,
                "actual_pass": actual_pass,
                "actual_fail": actual_fail,
                "mismatches": mismatches,
            }
        )
    return output


def metric_rows(runs: list[dict[str, str]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, int, int, int, str], list[dict[str, str]]] = defaultdict(list)
    for row in runs:
        arch = "trusted" if row["trusted"].lower() == "true" else "verified"
        grouped[
            (
                arch,
                int(row["nodes"]),
                int(row["quorum_size"]),
                int(row["prefill_byzantine_withholders_per_branch"]),
                row["latency_distribution"]
                if row["latency_distribution"] == "even"
                else f"random{row['latency_min_ms']}_{row['latency_max_ms']}",
            )
        ].append(row)

    output = []
    for (arch, nodes, quorum, withholders, latency), rows in sorted(grouped.items()):
        output.append(
            {
                "architecture": arch,
                "nodes": nodes,
                "quorum_size": quorum,
                "withholders_per_branch": withholders,
                "latency_profile": latency if latency != "even" else f"even{rows[0]['latency_ms']}",
                "epochs": len(rows),
                "missing_before_repair_total": sum(
                    int(row["subset_missing_payloads_before_repair"]) for row in rows
                ),
                "missing_after_repair_total": sum(
                    int(row["subset_missing_payloads_after_repair"]) for row in rows
                ),
                "payload_ready_ms_mean": f"{mean([float(row['subset_payload_ready_latency_ms']) for row in rows]):.2f}",
                "tps_mean": f"{mean([float(row['subset_payload_ready_tps']) for row in rows]):.2f}",
                "wire_mb_per_epoch_mean": f"{mean([float(row['subset_wire_bytes']) for row in rows]) / 1_000_000.0:.3f}",
                "per_node_gbps_mean": f"{mean([float(row['subset_per_node_gbps']) for row in rows]):.6f}",
            }
        )
    return output


def write_markdown(
    path: Path,
    manifest: list[dict[str, str]],
    statuses: list[dict[str, object]],
    metrics: list[dict[str, object]],
) -> None:
    mismatches = [
        row
        for row in manifest
        if row["expected_status"] != "any" and row["expected_status"] != row["actual_status"]
    ]
    pass_cases = sum(1 for row in manifest if row["actual_status"] == "pass")
    fail_cases = sum(1 for row in manifest if row["actual_status"] == "fail")
    verified_statuses = [row for row in statuses if row["architecture"] == "verified"]
    trusted_statuses = [row for row in statuses if row["architecture"] == "trusted"]

    with path.open("w") as handle:
        handle.write("# Prefill Safety Frontier\n\n")
        handle.write(f"- manifest cases: {len(manifest)}\n")
        handle.write(f"- actual passes: {pass_cases}\n")
        handle.write(f"- actual fails: {fail_cases}\n")
        handle.write(f"- expected/actual mismatches: {len(mismatches)}\n")
        handle.write(f"- verified policy groups: {len(verified_statuses)}\n")
        handle.write(f"- trusted policy groups: {len(trusted_statuses)}\n")
        if metrics:
            worst_missing = max(metrics, key=lambda row: int(row["missing_after_repair_total"]))
            fastest = max(metrics, key=lambda row: float(row["tps_mean"]))
            handle.write(
                f"- worst after-repair missing total in passing runs: {worst_missing['missing_after_repair_total']} "
                f"({worst_missing['architecture']}, n={worst_missing['nodes']}, q={worst_missing['quorum_size']}, "
                f"withholders={worst_missing['withholders_per_branch']})\n"
            )
            handle.write(
                f"- highest passing TPS mean: {fastest['tps_mean']} "
                f"({fastest['architecture']}, n={fastest['nodes']}, q={fastest['quorum_size']}, "
                f"withholders={fastest['withholders_per_branch']})\n"
            )
        if mismatches:
            handle.write("\n## Mismatches\n\n")
            for row in mismatches[:20]:
                handle.write(
                    f"- {row['scenario']}: expected {row['expected_status']}, got {row['actual_status']}\n"
                )


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: analyze-prefill-safety.py <prefill-safety-results-dir>", file=sys.stderr)
        return 2

    out_dir = Path(sys.argv[1])
    manifest = read_csv(out_dir / "prefill_safety_manifest.csv")
    runs = read_csv(out_dir / "subset_gossip_runs.csv")
    if not manifest:
        print(f"missing or empty {out_dir / 'prefill_safety_manifest.csv'}", file=sys.stderr)
        return 2

    statuses = status_rows(manifest)
    metrics = metric_rows(runs)
    write_csv(out_dir / "prefill_safety_status.csv", statuses)
    write_csv(out_dir / "prefill_safety_metrics.csv", metrics)
    write_markdown(out_dir / "prefill_safety_summary.md", manifest, statuses, metrics)

    print(out_dir)
    print(f"manifest_cases={len(manifest)}")
    print(f"status_groups={len(statuses)}")
    print(f"metric_groups={len(metrics)}")
    print(
        "mismatches="
        + str(
            sum(
                1
                for row in manifest
                if row["expected_status"] != "any"
                and row["expected_status"] != row["actual_status"]
            )
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
