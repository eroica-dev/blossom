#!/usr/bin/env python3
"""Summarize repeated Blossom proof-validation matrix output."""

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
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def read_single_row(path: Path) -> dict[str, str] | None:
    rows = read_rows(path)
    return rows[0] if rows else None


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        return
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def int_field(row: dict[str, str] | None, key: str, default: int = 0) -> int:
    if row is None:
        return default
    value = row.get(key, "")
    return default if value == "" else int(value)


def float_field(row: dict[str, str], key: str, default: float = 0.0) -> float:
    value = row.get(key, "")
    return default if value == "" else float(value)


def bool_field(row: dict[str, str] | None, key: str) -> bool:
    if row is None:
        return False
    return row.get(key, "").lower() == "true"


def ratio(numerator: float, denominator: float) -> float:
    return 0.0 if denominator == 0 else numerator / denominator


def pct(numerator: float, denominator: float) -> float:
    return ratio(numerator, denominator) * 100.0


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


def percentile(values: list[float], rank: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = (len(ordered) - 1) * rank
    low = math.floor(index)
    high = math.ceil(index)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (index - low)


def fmt(value: float, digits: int = 2) -> str:
    return f"{value:.{digits}f}"


def scenario_base(entry: dict[str, str]) -> str:
    return entry.get("base_scenario") or entry["scenario"]


def scenario_architecture(entry: dict[str, str]) -> str:
    if entry.get("architecture"):
        return entry["architecture"]
    return "trusted" if "_trusted" in entry["scenario"] else "verified"


def scenario_repeat(entry: dict[str, str]) -> int:
    return int(entry.get("repeat") or 1)


def scenario_nodes(entry: dict[str, str], row: dict[str, str] | None = None) -> int:
    if entry.get("nodes"):
        return int(entry["nodes"])
    return int_field(row, "nodes")


def summarize_chaos(manifest_rows: list[dict[str, str]]) -> list[dict[str, object]]:
    summaries: list[dict[str, object]] = []
    for entry in manifest_rows:
        if entry["kind"] != "chaos":
            continue

        row = read_single_row(Path(entry["summary"]))
        epoch_rows = read_rows(Path(entry["epochs"]))
        stderr_path = Path(entry["stderr"])
        stderr_tail = ""
        if stderr_path.exists():
            stderr_tail = " | ".join(stderr_path.read_text(errors="replace").splitlines()[-3:])

        expected = entry["expected_status"]
        actual = entry["actual_status"]
        pass_by_rejection = expected == "fail" and actual == "fail"
        correctness_pass = pass_by_rejection

        if row is not None:
            correctness_pass = (
                expected == "pass"
                and actual == "pass"
                and int_field(row, "final_incorrect_nodes") == 0
                and int_field(row, "final_data_unavailable_nodes") == 0
                and int_field(row, "final_unique_epoch_hashes") == 1
                and int_field(row, "incorrectly_lost_local_blocks") == 0
            )

        divergent_epochs = 0
        reconciled_epochs = 0
        if epoch_rows:
            divergent_epochs = sum(
                1
                for epoch in epoch_rows
                if int_field(epoch, "pre_repair_correct_nodes")
                < int_field(epoch, "active_nodes")
            )
            reconciled_epochs = sum(
                1 for epoch in epoch_rows if int_field(epoch, "repaired_nodes") > 0
            )

        total_messages = int_field(row, "total_messages")
        dropped = int_field(row, "dropped")
        fuzzed = int_field(row, "fuzzed")
        delivered = int_field(row, "delivered")

        summaries.append(
            {
                "base_scenario": scenario_base(entry),
                "scenario": entry["scenario"],
                "architecture": scenario_architecture(entry),
                "repeat": scenario_repeat(entry),
                "nodes": scenario_nodes(entry, row),
                "expected_status": expected,
                "actual_status": actual,
                "epochs": int_field(row, "epochs"),
                "trusted": str(bool_field(row, "trusted")).lower(),
                "total_messages": total_messages,
                "delivered": delivered,
                "dropped": dropped,
                "fuzzed": fuzzed,
                "spiked": int_field(row, "spiked"),
                "delivered_pct": pct(delivered, total_messages),
                "dropped_or_fuzzed_pct": pct(dropped + fuzzed, total_messages),
                "repaired_nodes": int_field(row, "repair_successes"),
                "reconnect_attempts": int_field(row, "reconnect_attempts"),
                "reconnect_successes": int_field(row, "reconnect_successes"),
                "reconnect_rejections": int_field(row, "reconnect_replays")
                + int_field(row, "reconnect_stale_proofs")
                + int_field(row, "reconnect_identity_rejections"),
                "final_active_nodes": int_field(row, "final_active_nodes"),
                "final_dropped_nodes": int_field(row, "final_dropped_nodes"),
                "final_correct_nodes": int_field(row, "final_correct_nodes"),
                "final_incorrect_nodes": int_field(row, "final_incorrect_nodes"),
                "final_data_unavailable_nodes": int_field(
                    row, "final_data_unavailable_nodes"
                ),
                "final_unique_epoch_hashes": int_field(row, "final_unique_epoch_hashes"),
                "valid_local_blocks": int_field(row, "valid_local_blocks"),
                "intentionally_dropped_local_blocks": int_field(
                    row, "intentionally_dropped_local_blocks"
                ),
                "incorrectly_lost_local_blocks": int_field(
                    row, "incorrectly_lost_local_blocks"
                ),
                "divergent_epochs": divergent_epochs,
                "reconciled_epochs": reconciled_epochs,
                "correctness_pass": str(correctness_pass).lower(),
                "stderr_tail": stderr_tail,
            }
        )
    return summaries


def summarize_throughput(manifest_rows: list[dict[str, str]]) -> list[dict[str, object]]:
    summaries: list[dict[str, object]] = []
    for entry in manifest_rows:
        if entry["kind"] != "throughput":
            continue
        rows = read_rows(Path(entry["summary"]))
        if not rows:
            continue

        first = rows[0]
        finality_ms = [float_field(row, "modeled_finality_latency_ms") for row in rows]
        modeled_ms = [float_field(row, "modeled_latency_ms") for row in rows]
        txs = [int_field(row, "epoch_transactions") for row in rows]
        wire = [int_field(row, "total_wire_bytes") for row in rows]
        block = [int_field(row, "block_bytes") for row in rows]
        finality_seconds = sum(finality_ms) / 1000.0
        total_wire_bytes = sum(wire)
        nodes = int(first["nodes"])

        stage_mbs = {}
        for stage in ("dispatch", "echo", "verification", "proposal", "commit"):
            stage_mbs[f"{stage}_mb_per_epoch"] = (
                mean(int_field(row, f"{stage}_bytes") for row in rows) / 1_000_000.0
            )

        summaries.append(
            {
                "base_scenario": scenario_base(entry),
                "scenario": entry["scenario"],
                "architecture": scenario_architecture(entry),
                "repeat": scenario_repeat(entry),
                "latency_profile": entry.get("latency_profile")
                or first["latency_distribution"],
                "nodes": nodes,
                "epochs": len(rows),
                "epoch_transactions": int(first["epoch_transactions"]),
                "quorum_size": int(first["quorum_size"]),
                "rounds": int(first["rounds"]),
                "converged_epochs": sum(1 for row in rows if row["converged"] == "true"),
                "finality_ms_avg": mean(finality_ms),
                "finality_ms_p95": percentile(finality_ms, 0.95),
                "modeled_latency_ms_avg": mean(modeled_ms),
                "tps_finality": sum(txs) / finality_seconds,
                "total_gbps": total_wire_bytes * 8.0 / finality_seconds / 1_000_000_000.0,
                "per_node_gbps": total_wire_bytes
                * 8.0
                / finality_seconds
                / 1_000_000_000.0
                / nodes,
                "amplification": ratio(sum(wire), sum(block)),
                "epoch_size_mb": mean(block) / 1_000_000.0,
                "wire_mb_per_epoch": mean(wire) / 1_000_000.0,
                **stage_mbs,
            }
        )
    return summaries


def aggregate_chaos(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[object, ...], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[
            (
                row["base_scenario"],
                row["architecture"],
                row["nodes"],
                row["expected_status"],
            )
        ].append(row)

    output = []
    for (base, architecture, nodes, expected), items in sorted(grouped.items()):
        values = lambda key: [float(item[key]) for item in items]
        output.append(
            {
                "base_scenario": base,
                "architecture": architecture,
                "nodes": nodes,
                "expected_status": expected,
                "runs": len(items),
                "pass_runs": sum(1 for item in items if item["correctness_pass"] == "true"),
                "epochs_per_run_mean": fmt(mean(values("epochs")), 2),
                "divergent_epochs_mean": fmt(mean(values("divergent_epochs")), 2),
                "divergent_epochs_std": fmt(stddev(values("divergent_epochs")), 2),
                "divergent_epochs_ci95": fmt(ci95(values("divergent_epochs")), 2),
                "repaired_nodes_mean": fmt(mean(values("repaired_nodes")), 2),
                "repaired_nodes_std": fmt(stddev(values("repaired_nodes")), 2),
                "repaired_nodes_ci95": fmt(ci95(values("repaired_nodes")), 2),
                "reconnect_attempts_mean": fmt(mean(values("reconnect_attempts")), 2),
                "reconnect_attempts_std": fmt(stddev(values("reconnect_attempts")), 2),
                "dropped_or_fuzzed_pct_mean": fmt(mean(values("dropped_or_fuzzed_pct")), 4),
                "dropped_or_fuzzed_pct_std": fmt(stddev(values("dropped_or_fuzzed_pct")), 4),
                "incorrectly_lost_total": int(sum(values("incorrectly_lost_local_blocks"))),
                "intentionally_dropped_mean": fmt(
                    mean(values("intentionally_dropped_local_blocks")), 2
                ),
                "final_incorrect_total": int(sum(values("final_incorrect_nodes"))),
                "final_data_unavailable_total": int(
                    sum(values("final_data_unavailable_nodes"))
                ),
            }
        )
    return output


def aggregate_throughput(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[object, ...], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[
            (
                row["base_scenario"],
                row["architecture"],
                row["latency_profile"],
                row["nodes"],
            )
        ].append(row)

    output = []
    for (base, architecture, latency_profile, nodes), items in sorted(grouped.items()):
        values = lambda key: [float(item[key]) for item in items]
        output.append(
            {
                "base_scenario": base,
                "architecture": architecture,
                "latency_profile": latency_profile,
                "nodes": nodes,
                "runs": len(items),
                "epochs_per_run_mean": fmt(mean(values("epochs")), 2),
                "converged_epochs_min": int(min(values("converged_epochs"))),
                "finality_ms_mean": fmt(mean(values("finality_ms_avg")), 2),
                "finality_ms_std": fmt(stddev(values("finality_ms_avg")), 2),
                "finality_ms_ci95": fmt(ci95(values("finality_ms_avg")), 2),
                "tps_mean": fmt(mean(values("tps_finality")), 2),
                "tps_std": fmt(stddev(values("tps_finality")), 2),
                "tps_ci95": fmt(ci95(values("tps_finality")), 2),
                "total_gbps_mean": fmt(mean(values("total_gbps")), 6),
                "total_gbps_std": fmt(stddev(values("total_gbps")), 6),
                "total_gbps_ci95": fmt(ci95(values("total_gbps")), 6),
                "per_node_gbps_mean": fmt(mean(values("per_node_gbps")), 6),
                "per_node_gbps_std": fmt(stddev(values("per_node_gbps")), 6),
                "per_node_gbps_ci95": fmt(ci95(values("per_node_gbps")), 6),
                "amplification_mean": fmt(mean(values("amplification")), 3),
                "amplification_std": fmt(stddev(values("amplification")), 3),
                "amplification_ci95": fmt(ci95(values("amplification")), 3),
                "epoch_size_mb_mean": fmt(mean(values("epoch_size_mb")), 3),
                "wire_mb_per_epoch_mean": fmt(mean(values("wire_mb_per_epoch")), 3),
                "dispatch_mb_per_epoch_mean": fmt(mean(values("dispatch_mb_per_epoch")), 3),
                "echo_mb_per_epoch_mean": fmt(mean(values("echo_mb_per_epoch")), 3),
                "verification_mb_per_epoch_mean": fmt(
                    mean(values("verification_mb_per_epoch")), 3
                ),
                "proposal_mb_per_epoch_mean": fmt(mean(values("proposal_mb_per_epoch")), 3),
                "commit_mb_per_epoch_mean": fmt(mean(values("commit_mb_per_epoch")), 3),
            }
        )
    return output


def row_lookup(
    rows: list[dict[str, object]],
    architecture: str,
    latency_profile: str,
    nodes: int,
) -> dict[str, object] | None:
    for row in rows:
        if (
            row["architecture"] == architecture
            and row["latency_profile"] == latency_profile
            and int(row["nodes"]) == nodes
        ):
            return row
    return None


def latex_coordinates(
    rows: list[dict[str, object]],
    architecture: str,
    latency_profile: str,
    metric: str,
    ci_metric: str,
    nodes: list[int],
) -> str:
    coords = []
    for node in nodes:
        row = row_lookup(rows, architecture, latency_profile, node)
        if row is None:
            continue
        coords.append(f"({node},{row[metric]}) +- (0,{row[ci_metric]})")
    return " ".join(coords)


def write_latex_plots(path: Path, throughput: list[dict[str, object]]) -> None:
    nodes = [6, 12, 36, 64]
    with path.open("w") as handle:
        handle.write("% Generated by benchmarks/scripts/analyze-proof-validation.py\n")
        handle.write("\\begin{figure}[h]\n\\centering\n")
        handle.write("\\begin{tikzpicture}\n")
        handle.write(
            "\\begin{axis}[width=0.86\\textwidth,height=6cm,xlabel={Nodes},ylabel={Modeled TPS},legend pos=north west,grid=both]\n"
        )
        handle.write(
            "\\addplot+[mark=*,error bars/.cd,y dir=both,y explicit] coordinates {"
            + latex_coordinates(throughput, "verified", "even150", "tps_mean", "tps_ci95", nodes)
            + "};\n"
        )
        handle.write("\\addlegendentry{verified, 150 ms}\n")
        handle.write(
            "\\addplot+[mark=square*,error bars/.cd,y dir=both,y explicit] coordinates {"
            + latex_coordinates(throughput, "trusted", "even150", "tps_mean", "tps_ci95", nodes)
            + "};\n"
        )
        handle.write("\\addlegendentry{trusted, 150 ms}\n")
        handle.write("\\end{axis}\n\\end{tikzpicture}\n")
        handle.write("\\caption{TPS by network size with 95\\% confidence intervals.}\n")
        handle.write("\\end{figure}\n\n")

        handle.write("\\begin{figure}[h]\n\\centering\n")
        handle.write("\\begin{tikzpicture}\n")
        handle.write(
            "\\begin{axis}[width=0.86\\textwidth,height=6cm,xlabel={Nodes},ylabel={Per-node Gb/s},legend pos=north west,grid=both]\n"
        )
        handle.write(
            "\\addplot+[mark=*,error bars/.cd,y dir=both,y explicit] coordinates {"
            + latex_coordinates(
                throughput,
                "verified",
                "even150",
                "per_node_gbps_mean",
                "per_node_gbps_ci95",
                nodes,
            )
            + "};\n"
        )
        handle.write("\\addlegendentry{verified, 150 ms}\n")
        handle.write(
            "\\addplot+[mark=square*,error bars/.cd,y dir=both,y explicit] coordinates {"
            + latex_coordinates(
                throughput,
                "trusted",
                "even150",
                "per_node_gbps_mean",
                "per_node_gbps_ci95",
                nodes,
            )
            + "};\n"
        )
        handle.write("\\addlegendentry{trusted, 150 ms}\n")
        handle.write("\\end{axis}\n\\end{tikzpicture}\n")
        handle.write("\\caption{Required per-node traffic capacity at modeled max throughput.}\n")
        handle.write("\\end{figure}\n\n")

        handle.write("\\begin{figure}[h]\n\\centering\n")
        handle.write("\\begin{tikzpicture}\n")
        handle.write(
            "\\begin{axis}[width=0.86\\textwidth,height=6cm,xlabel={One-way even latency (ms)},ylabel={Modeled finality (ms)},legend pos=north west,grid=both]\n"
        )
        for architecture, mark in (("verified", "*"), ("trusted", "square*")):
            coords = []
            for latency in (50, 150, 300):
                row = row_lookup(throughput, architecture, f"even{latency}", 36)
                if row is not None:
                    coords.append(
                        f"({latency},{row['finality_ms_mean']}) +- (0,{row['finality_ms_ci95']})"
                    )
            handle.write(
                f"\\addplot+[mark={mark},error bars/.cd,y dir=both,y explicit] coordinates {{{' '.join(coords)}}};\n"
            )
            handle.write(f"\\addlegendentry{{{architecture}, 36 nodes}}\n")
        handle.write("\\end{axis}\n\\end{tikzpicture}\n")
        handle.write("\\caption{Latency sensitivity for the same 36-node workload.}\n")
        handle.write("\\end{figure}\n")


def write_markdown_report(
    path: Path,
    chaos: list[dict[str, object]],
    chaos_agg: list[dict[str, object]],
    throughput: list[dict[str, object]],
    throughput_agg: list[dict[str, object]],
) -> None:
    pass_count = sum(1 for item in chaos if item["correctness_pass"] == "true")
    lost = sum(
        int(item["incorrectly_lost_local_blocks"])
        for item in chaos
        if item["expected_status"] == "pass"
    )
    best = max(throughput, key=lambda item: float(item["tps_finality"]))
    worst_amp = max(throughput, key=lambda item: float(item["amplification"]))
    run_counts = sorted({int(item["runs"]) for item in throughput_agg})

    with path.open("w") as handle:
        handle.write("# Blossom Repeated Proof Validation Analysis\n\n")
        handle.write(f"- chaos run rows validated: {pass_count}/{len(chaos)}\n")
        handle.write(f"- throughput run rows: {len(throughput)}\n")
        handle.write(f"- repeated-run counts observed: {run_counts}\n")
        handle.write(f"- long-run incorrectly lost blocks: {lost}\n")
        handle.write(
            f"- highest modeled TPS: {best['scenario']} at {float(best['tps_finality']):.0f} TPS\n"
        )
        handle.write(
            f"- highest bandwidth amplification: {worst_amp['scenario']} at {float(worst_amp['amplification']):.2f}x\n"
        )
        handle.write(f"- chaos aggregate rows: {len(chaos_agg)}\n")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: analyze-proof-validation.py <proof-validation-results-dir>", file=sys.stderr)
        return 2

    out_dir = Path(sys.argv[1])
    manifest_path = out_dir / "run_manifest.csv"
    if not manifest_path.exists():
        print(f"missing manifest: {manifest_path}", file=sys.stderr)
        return 2

    manifest_rows = read_rows(manifest_path)
    chaos = summarize_chaos(manifest_rows)
    throughput = summarize_throughput(manifest_rows)
    chaos_agg = aggregate_chaos(chaos)
    throughput_agg = aggregate_throughput(throughput)

    write_csv(out_dir / "chaos_summary.csv", chaos)
    write_csv(out_dir / "throughput_summary.csv", throughput)
    write_csv(out_dir / "chaos_aggregate.csv", chaos_agg)
    write_csv(out_dir / "throughput_aggregate.csv", throughput_agg)
    write_latex_plots(out_dir / "validation_repeated_plots.tex", throughput_agg)
    write_markdown_report(
        out_dir / "analysis_summary.md", chaos, chaos_agg, throughput, throughput_agg
    )

    print(out_dir)
    print(f"chaos_run_rows={len(chaos)}")
    print(f"throughput_run_rows={len(throughput)}")
    print(f"chaos_aggregate_rows={len(chaos_agg)}")
    print(f"throughput_aggregate_rows={len(throughput_agg)}")
    print(f"chaos_correctness_passes={sum(1 for item in chaos if item['correctness_pass'] == 'true')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
