#!/usr/bin/env python3
"""Summarize repeated subset block gossip benchmark output."""

from __future__ import annotations

import csv
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable


T_CRITICAL_95 = {
    1: 12.706,
    2: 4.303,
    3: 3.182,
    4: 2.776,
    5: 2.571,
    6: 2.447,
    7: 2.365,
    8: 2.306,
    9: 2.262,
    10: 2.228,
}


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        return
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def f(row: dict[str, str], key: str) -> float:
    value = row.get(key, "")
    return 0.0 if value == "" else float(value)


def i(row: dict[str, str], key: str) -> int:
    value = row.get(key, "")
    return 0 if value == "" else int(value)


def b(row: dict[str, str], key: str) -> bool:
    return row.get(key, "").lower() == "true"


def mean(values: Iterable[float]) -> float:
    values = list(values)
    return statistics.fmean(values) if values else 0.0


def stddev(values: Iterable[float]) -> float:
    values = list(values)
    return statistics.stdev(values) if len(values) > 1 else 0.0


def ci95(values: Iterable[float]) -> float:
    values = list(values)
    if len(values) <= 1:
        return 0.0
    t = T_CRITICAL_95.get(len(values) - 1, 1.96)
    return t * statistics.stdev(values) / math.sqrt(len(values))


def fmt(value: float, digits: int = 3) -> str:
    return f"{value:.{digits}f}"


def latency_profile(row: dict[str, str]) -> str:
    if row["latency_distribution"] == "even":
        return f"even{row['latency_ms']}"
    return f"random{row['latency_min_ms']}_{row['latency_max_ms']}"


def architecture(row: dict[str, str]) -> str:
    return "trusted" if b(row, "trusted") else "verified"


def protocol_version(row: dict[str, str]) -> str:
    value = row.get("protocol_version", "")
    if value:
        return value
    if row.get("prefill_mode") == "prefill-dispatch" and not b(row, "repair_missing"):
        return "v2"
    if row.get("prefill_mode") == "none" and b(row, "repair_missing"):
        return "v1"
    return "custom"


def fault_profile(row: dict[str, str]) -> str:
    withholders = i(row, "prefill_byzantine_withholders_per_branch")
    drop_round0 = b(row, "drop_round0_dispatch")
    if drop_round0 and withholders > 0:
        return f"round0_drop+prefill_withhold{withholders}"
    if drop_round0:
        return "round0_drop"
    if withholders > 0:
        return f"prefill_withhold{withholders}"
    return "clean"


def summarize_runs(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    grouped: dict[tuple[object, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[
            (
                row["scenario"],
                int(row["repeat"]),
                protocol_version(row),
                architecture(row),
                fault_profile(row),
                latency_profile(row),
                int(row["nodes"]),
                int(row["quorum_size"]),
                int(row["targets_per_command"]),
                int(row["prefill_byzantine_withholders_per_branch"]),
            )
        ].append(row)

    summaries = []
    for (
        scenario,
        repeat,
        version,
        arch,
        fault,
        latency,
        nodes,
        quorum_size,
        targets,
        withholders,
    ), items in sorted(grouped.items()):
        full_latency_seconds = sum(f(row, "modeled_finality_latency_ms") for row in items) / 1000.0
        subset_latency_seconds = (
            sum(f(row, "subset_payload_ready_latency_ms") for row in items) / 1000.0
        )
        total_commands = sum(i(row, "total_commands") for row in items)
        full_wire = sum(i(row, "full_wire_bytes") for row in items)
        subset_wire = sum(i(row, "subset_wire_bytes") for row in items)
        full_block = sum(i(row, "full_block_bytes") for row in items)
        target_deliveries = sum(i(row, "target_payload_deliveries") for row in items)
        missing_before = sum(i(row, "subset_missing_payloads_before_repair") for row in items)
        missing_after = sum(i(row, "subset_missing_payloads_after_repair") for row in items)

        summaries.append(
            {
                "scenario": scenario,
                "repeat": repeat,
                "protocol_version": version,
                "architecture": arch,
                "fault_profile": fault,
                "latency_profile": latency,
                "nodes": nodes,
                "quorum_size": quorum_size,
                "targets_per_command": targets,
                "prefill_byzantine_withholders_per_branch": withholders,
                "epochs": len(items),
                "rounds_mean": mean(i(row, "rounds") for row in items),
                "quorums_mean": mean(i(row, "quorums") for row in items),
                "prefill_fanout_mean": mean(i(row, "prefill_fanout") for row in items),
                "prefill_skip_rounds_max": max(i(row, "prefill_skip_rounds") for row in items),
                "metadata_converged_epochs": sum(1 for row in items if b(row, "metadata_converged")),
                "payload_complete_before_repair_epochs": sum(
                    1 for row in items if b(row, "subset_payloads_complete_before_repair")
                ),
                "payload_complete_epochs": sum(
                    1 for row in items if b(row, "subset_payloads_complete_after_repair")
                ),
                "target_payload_deliveries": target_deliveries,
                "missing_before_repair": missing_before,
                "missing_before_repair_pct": (
                    0.0 if target_deliveries == 0 else missing_before * 100.0 / target_deliveries
                ),
                "missing_after_repair": missing_after,
                "repair_batches": sum(i(row, "subset_repair_batches") for row in items),
                "repair_bytes_mb_per_epoch": mean(i(row, "subset_repair_bytes") for row in items)
                / 1_000_000.0,
                "full_finality_ms_mean": mean(f(row, "modeled_finality_latency_ms") for row in items),
                "subset_payload_ready_ms_mean": mean(
                    f(row, "subset_payload_ready_latency_ms") for row in items
                ),
                "full_tps": 0.0 if full_latency_seconds == 0 else total_commands / full_latency_seconds,
                "subset_payload_ready_tps": (
                    0.0 if subset_latency_seconds == 0 else total_commands / subset_latency_seconds
                ),
                "full_wire_mb_per_epoch": mean(i(row, "full_wire_bytes") for row in items)
                / 1_000_000.0,
                "subset_wire_mb_per_epoch": mean(i(row, "subset_wire_bytes") for row in items)
                / 1_000_000.0,
                "full_gbps": (
                    0.0 if full_latency_seconds == 0 else full_wire * 8.0 / full_latency_seconds / 1_000_000_000.0
                ),
                "subset_gbps": (
                    0.0
                    if subset_latency_seconds == 0
                    else subset_wire * 8.0 / subset_latency_seconds / 1_000_000_000.0
                ),
                "full_per_node_gbps": (
                    0.0
                    if full_latency_seconds == 0
                    else full_wire * 8.0 / full_latency_seconds / 1_000_000_000.0 / nodes
                ),
                "subset_per_node_gbps": (
                    0.0
                    if subset_latency_seconds == 0
                    else subset_wire * 8.0 / subset_latency_seconds / 1_000_000_000.0 / nodes
                ),
                "full_amplification": 0.0 if full_block == 0 else full_wire / full_block,
                "subset_amplification": 0.0 if full_block == 0 else subset_wire / full_block,
                "subset_savings_pct": 0.0 if full_wire == 0 else (full_wire - subset_wire) * 100.0 / full_wire,
            }
        )
    return summaries


def aggregate_runs(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[object, ...], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[
            (
                row["protocol_version"],
                row["architecture"],
                row["fault_profile"],
                row["latency_profile"],
                row["nodes"],
                row["quorum_size"],
                row["targets_per_command"],
                row["prefill_byzantine_withholders_per_branch"],
            )
        ].append(row)

    output = []
    for (
        version,
        arch,
        fault,
        latency,
        nodes,
        quorum_size,
        targets,
        withholders,
    ), items in sorted(grouped.items()):
        values = lambda key: [float(item[key]) for item in items]
        output.append(
            {
                "protocol_version": version,
                "architecture": arch,
                "fault_profile": fault,
                "latency_profile": latency,
                "nodes": nodes,
                "quorum_size": quorum_size,
                "targets_per_command": targets,
                "prefill_byzantine_withholders_per_branch": withholders,
                "runs": len(items),
                "epochs_per_run_mean": fmt(mean(values("epochs")), 2),
                "rounds_mean": fmt(mean(values("rounds_mean")), 2),
                "quorums_mean": fmt(mean(values("quorums_mean")), 2),
                "prefill_fanout_mean": fmt(mean(values("prefill_fanout_mean")), 2),
                "prefill_skip_rounds_max": int(max(values("prefill_skip_rounds_max"))),
                "metadata_converged_min": int(min(values("metadata_converged_epochs"))),
                "payload_complete_before_repair_rate_mean": fmt(
                    mean(
                        float(item["payload_complete_before_repair_epochs"])
                        * 100.0
                        / max(float(item["epochs"]), 1.0)
                        for item in items
                    ),
                    3,
                ),
                "payload_complete_min": int(min(values("payload_complete_epochs"))),
                "payload_complete_after_repair_rate_mean": fmt(
                    mean(
                        float(item["payload_complete_epochs"])
                        * 100.0
                        / max(float(item["epochs"]), 1.0)
                        for item in items
                    ),
                    3,
                ),
                "missing_before_repair_pct_mean": fmt(mean(values("missing_before_repair_pct")), 4),
                "missing_after_repair_total": int(sum(values("missing_after_repair"))),
                "repair_batches_mean": fmt(mean(values("repair_batches")), 2),
                "full_finality_ms_mean": fmt(mean(values("full_finality_ms_mean")), 2),
                "subset_payload_ready_ms_mean": fmt(mean(values("subset_payload_ready_ms_mean")), 2),
                "subset_payload_ready_ms_std": fmt(stddev(values("subset_payload_ready_ms_mean")), 2),
                "subset_payload_ready_ms_ci95": fmt(ci95(values("subset_payload_ready_ms_mean")), 2),
                "full_tps_mean": fmt(mean(values("full_tps")), 2),
                "subset_tps_mean": fmt(mean(values("subset_payload_ready_tps")), 2),
                "subset_tps_std": fmt(stddev(values("subset_payload_ready_tps")), 2),
                "subset_tps_ci95": fmt(ci95(values("subset_payload_ready_tps")), 2),
                "full_wire_mb_per_epoch_mean": fmt(mean(values("full_wire_mb_per_epoch")), 3),
                "subset_wire_mb_per_epoch_mean": fmt(mean(values("subset_wire_mb_per_epoch")), 3),
                "repair_bytes_mb_per_epoch_mean": fmt(mean(values("repair_bytes_mb_per_epoch")), 3),
                "full_gbps_mean": fmt(mean(values("full_gbps")), 6),
                "subset_gbps_mean": fmt(mean(values("subset_gbps")), 6),
                "subset_gbps_std": fmt(stddev(values("subset_gbps")), 6),
                "subset_gbps_ci95": fmt(ci95(values("subset_gbps")), 6),
                "full_per_node_gbps_mean": fmt(mean(values("full_per_node_gbps")), 6),
                "subset_per_node_gbps_mean": fmt(mean(values("subset_per_node_gbps")), 6),
                "subset_per_node_gbps_std": fmt(stddev(values("subset_per_node_gbps")), 6),
                "subset_per_node_gbps_ci95": fmt(ci95(values("subset_per_node_gbps")), 6),
                "full_amplification_mean": fmt(mean(values("full_amplification")), 3),
                "subset_amplification_mean": fmt(mean(values("subset_amplification")), 3),
                "subset_savings_pct_mean": fmt(mean(values("subset_savings_pct")), 3),
                "subset_savings_pct_std": fmt(stddev(values("subset_savings_pct")), 3),
                "subset_savings_pct_ci95": fmt(ci95(values("subset_savings_pct")), 3),
            }
        )
    return output


def compare_v2_to_v1(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[object, ...], dict[str, dict[str, object]]] = defaultdict(dict)
    for row in rows:
        grouped[
            (
                row["architecture"],
                row["fault_profile"],
                row["latency_profile"],
                row["nodes"],
                row["quorum_size"],
                row["targets_per_command"],
                row["prefill_byzantine_withholders_per_branch"],
            )
        ][str(row["protocol_version"])] = row

    output = []
    for (
        arch,
        fault,
        latency,
        nodes,
        quorum_size,
        targets,
        withholders,
    ), versions in sorted(grouped.items()):
        v1 = versions.get("v1")
        v2 = versions.get("v2")
        if v1 is None or v2 is None:
            continue

        v1_latency = float(v1["subset_payload_ready_ms_mean"])
        v2_latency = float(v2["subset_payload_ready_ms_mean"])
        v1_tps = float(v1["subset_tps_mean"])
        v2_tps = float(v2["subset_tps_mean"])
        v1_wire = float(v1["subset_wire_mb_per_epoch_mean"])
        v2_wire = float(v2["subset_wire_mb_per_epoch_mean"])
        v1_missing_before = float(v1["missing_before_repair_pct_mean"])
        v2_missing_before = float(v2["missing_before_repair_pct_mean"])
        v1_repairs = float(v1["repair_batches_mean"])
        v2_repairs = float(v2["repair_batches_mean"])
        v1_rounds = float(v1["rounds_mean"])
        v2_rounds = float(v2["rounds_mean"])
        v1_before_success = float(v1["payload_complete_before_repair_rate_mean"])
        v2_before_success = float(v2["payload_complete_before_repair_rate_mean"])
        v1_after_success = float(v1["payload_complete_after_repair_rate_mean"])
        v2_after_success = float(v2["payload_complete_after_repair_rate_mean"])

        v2_complete_without_repair = (
            v2_missing_before == 0.0
            and int(v2["missing_after_repair_total"]) == 0
            and v2_repairs == 0.0
        )
        v1_repair_dependent = v1_missing_before > 0.0 or v1_repairs > 0.0
        v2_faster = v2_latency < v1_latency and v2_tps > v1_tps
        v2_less_wire = v2_wire < v1_wire

        output.append(
            {
                "architecture": arch,
                "fault_profile": fault,
                "latency_profile": latency,
                "nodes": nodes,
                "quorum_size": quorum_size,
                "targets_per_command": targets,
                "prefill_byzantine_withholders_per_branch": withholders,
                "v1_rounds_mean": fmt(v1_rounds, 2),
                "v2_rounds_mean": fmt(v2_rounds, 2),
                "rounds_saved": fmt(v1_rounds - v2_rounds, 2),
                "v1_missing_before_repair_pct": fmt(v1_missing_before, 4),
                "v2_missing_before_repair_pct": fmt(v2_missing_before, 4),
                "missing_before_repair_reduction_pct_points": fmt(
                    v1_missing_before - v2_missing_before, 4
                ),
                "v1_payload_complete_before_repair_rate_pct": fmt(v1_before_success, 3),
                "v2_prefill_success_rate_pct": fmt(v2_before_success, 3),
                "prefill_success_rate_delta_pct_points": fmt(
                    v2_before_success - v1_before_success, 3
                ),
                "v1_payload_complete_after_repair_rate_pct": fmt(v1_after_success, 3),
                "v2_payload_complete_after_repair_rate_pct": fmt(v2_after_success, 3),
                "v1_repair_batches_mean": fmt(v1_repairs, 2),
                "v2_repair_batches_mean": fmt(v2_repairs, 2),
                "v1_subset_payload_ready_ms_mean": fmt(v1_latency, 2),
                "v2_subset_payload_ready_ms_mean": fmt(v2_latency, 2),
                "v2_latency_reduction_pct": fmt(
                    0.0 if v1_latency == 0 else (v1_latency - v2_latency) * 100.0 / v1_latency,
                    3,
                ),
                "v1_subset_tps_mean": fmt(v1_tps, 2),
                "v2_subset_tps_mean": fmt(v2_tps, 2),
                "v2_tps_uplift_pct": fmt(
                    0.0 if v1_tps == 0 else (v2_tps - v1_tps) * 100.0 / v1_tps,
                    3,
                ),
                "v1_subset_wire_mb_per_epoch_mean": fmt(v1_wire, 3),
                "v2_subset_wire_mb_per_epoch_mean": fmt(v2_wire, 3),
                "v2_wire_reduction_pct": fmt(
                    0.0 if v1_wire == 0 else (v1_wire - v2_wire) * 100.0 / v1_wire,
                    3,
                ),
                "v2_complete_without_repair": str(v2_complete_without_repair).lower(),
                "v1_repair_dependent": str(v1_repair_dependent).lower(),
                "v2_faster": str(v2_faster).lower(),
                "v2_less_wire": str(v2_less_wire).lower(),
                "safety_claim_pass": str(
                    v2_complete_without_repair and v1_repair_dependent
                ).lower(),
                "performance_claim_pass": str(v2_faster and v2_less_wire).lower(),
            }
        )

    return output


def row_for(
    rows: list[dict[str, object]],
    version: str,
    arch: str,
    fault: str,
    latency: str,
    nodes: int,
    targets: int,
    quorum_size: int = 6,
    withholders: int = 0,
) -> dict[str, object] | None:
    for row in rows:
        if (
            row["protocol_version"] == version
            and row["architecture"] == arch
            and row["fault_profile"] == fault
            and row["latency_profile"] == latency
            and int(row["nodes"]) == nodes
            and int(row["quorum_size"]) == quorum_size
            and int(row["targets_per_command"]) == targets
            and int(row["prefill_byzantine_withholders_per_branch"]) == withholders
        ):
            return row
    return None


def write_plots(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w") as handle:
        handle.write("% Generated by benchmarks/scripts/analyze-subset-gossip.py\n")
        handle.write("\\begin{figure}[h]\n\\centering\n\\begin{tikzpicture}\n")
        handle.write(
            "\\begin{axis}[width=0.86\\textwidth,height=6cm,xlabel={Targets per command},ylabel={Wire savings (\\%)},legend pos=south east,grid=both]\n"
        )
        for arch, mark in (("verified", "*"), ("trusted", "square*")):
            coords = []
            for targets in (1, 3, 6):
                row = row_for(rows, "v2", arch, "clean", "even150", 64, targets)
                if row is None:
                    row = row_for(rows, "v1", arch, "clean", "even150", 64, targets)
                if row:
                    coords.append(
                        f"({targets},{row['subset_savings_pct_mean']}) +- (0,{row['subset_savings_pct_ci95']})"
                    )
            handle.write(
                f"\\addplot+[mark={mark},error bars/.cd,y dir=both,y explicit] coordinates {{{' '.join(coords)}}};\n"
            )
            handle.write(f"\\addlegendentry{{{arch}, 64 nodes}}\n")
        handle.write("\\end{axis}\n\\end{tikzpicture}\n")
        handle.write("\\caption{Subset block gossip wire savings at 64 nodes and 150 ms latency.}\n")
        handle.write("\\end{figure}\n\n")

        handle.write("\\begin{figure}[h]\n\\centering\n\\begin{tikzpicture}\n")
        handle.write(
            "\\begin{axis}[width=0.86\\textwidth,height=6cm,xlabel={Nodes},ylabel={Subset per-node Gb/s},legend pos=north west,grid=both]\n"
        )
        for targets, mark in ((1, "*"), (3, "square*"), (6, "triangle*")):
            coords = []
            for nodes in (12, 36, 64):
                row = row_for(rows, "v2", "verified", "clean", "even150", nodes, targets)
                if row is None:
                    row = row_for(rows, "v1", "verified", "clean", "even150", nodes, targets)
                if row:
                    coords.append(
                        f"({nodes},{row['subset_per_node_gbps_mean']}) +- (0,{row['subset_per_node_gbps_ci95']})"
                    )
            handle.write(
                f"\\addplot+[mark={mark},error bars/.cd,y dir=both,y explicit] coordinates {{{' '.join(coords)}}};\n"
            )
            handle.write(f"\\addlegendentry{{verified, targets={targets}}}\n")
        handle.write("\\end{axis}\n\\end{tikzpicture}\n")
        handle.write("\\caption{Verified subset block gossip per-node bandwidth by network size.}\n")
        handle.write("\\end{figure}\n")


def write_markdown(
    path: Path,
    summaries: list[dict[str, object]],
    aggregates: list[dict[str, object]],
    comparisons: list[dict[str, object]],
) -> None:
    total_epochs = sum(int(row["epochs"]) for row in summaries)
    complete_runs = sum(
        1
        for row in summaries
        if int(row["metadata_converged_epochs"]) == int(row["epochs"])
        and int(row["payload_complete_epochs"]) == int(row["epochs"])
        and int(row["missing_after_repair"]) == 0
    )
    best = max(aggregates, key=lambda row: float(row["subset_savings_pct_mean"]))
    worst_missing = max(summaries, key=lambda row: float(row["missing_before_repair_pct"]))
    safety_passes = sum(1 for row in comparisons if row["safety_claim_pass"] == "true")
    performance_passes = sum(1 for row in comparisons if row["performance_claim_pass"] == "true")
    best_latency = (
        max(comparisons, key=lambda row: float(row["v2_latency_reduction_pct"]))
        if comparisons
        else None
    )
    weakest_wire = (
        min(comparisons, key=lambda row: float(row["v2_wire_reduction_pct"]))
        if comparisons
        else None
    )

    with path.open("w") as handle:
        handle.write("# Subset Block Gossip Analysis\n\n")
        handle.write(f"- run groups: {len(summaries)}\n")
        handle.write(f"- aggregate groups: {len(aggregates)}\n")
        handle.write(f"- v2-vs-v1 comparison groups: {len(comparisons)}\n")
        handle.write(f"- modeled epochs: {total_epochs}\n")
        handle.write(f"- complete metadata/payload runs after repair: {complete_runs}/{len(summaries)}\n")
        handle.write(
            f"- best mean wire savings: {best['subset_savings_pct_mean']}% "
            f"({best['protocol_version']}, {best['architecture']}, {best['latency_profile']}, n={best['nodes']}, targets={best['targets_per_command']})\n"
        )
        handle.write(
            f"- highest before-repair missing target payload rate: {float(worst_missing['missing_before_repair_pct']):.2f}% "
            f"({worst_missing['scenario']})\n"
        )
        if comparisons:
            handle.write(
                f"- v2 safety claim pass groups: {safety_passes}/{len(comparisons)} "
                "(v2 complete before repair while v1 needed repair)\n"
            )
            handle.write(
                f"- v2 performance claim pass groups: {performance_passes}/{len(comparisons)} "
                "(v2 lower latency/TPS higher and lower wire than v1)\n"
            )
        if best_latency is not None:
            handle.write(
                f"- strongest v2 latency reduction: {best_latency['v2_latency_reduction_pct']}% "
                f"({best_latency['architecture']}, {best_latency['latency_profile']}, "
                f"n={best_latency['nodes']}, targets={best_latency['targets_per_command']})\n"
            )
        if weakest_wire is not None:
            handle.write(
                f"- weakest v2 wire reduction: {weakest_wire['v2_wire_reduction_pct']}% "
                f"({weakest_wire['architecture']}, {weakest_wire['latency_profile']}, "
                f"n={weakest_wire['nodes']}, targets={weakest_wire['targets_per_command']})\n"
            )


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: analyze-subset-gossip.py <subset-gossip-results-dir>", file=sys.stderr)
        return 2

    out_dir = Path(sys.argv[1])
    source = out_dir / "subset_gossip_runs.csv"
    if not source.exists():
        print(f"missing {source}", file=sys.stderr)
        return 2

    summaries = summarize_runs(read_rows(source))
    aggregates = aggregate_runs(summaries)
    comparisons = compare_v2_to_v1(aggregates)
    write_csv(out_dir / "subset_gossip_summary.csv", summaries)
    write_csv(out_dir / "subset_gossip_aggregate.csv", aggregates)
    write_csv(out_dir / "subset_gossip_v2_vs_v1.csv", comparisons)
    write_plots(out_dir / "subset_gossip_plots.tex", aggregates)
    write_markdown(out_dir / "analysis_summary.md", summaries, aggregates, comparisons)

    print(out_dir)
    print(f"run_groups={len(summaries)}")
    print(f"aggregate_groups={len(aggregates)}")
    print(f"comparison_groups={len(comparisons)}")
    print(f"complete_runs={sum(1 for row in summaries if int(row['missing_after_repair']) == 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
