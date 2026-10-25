"""Final empirical analysis for WAF evaluation CSV datasets."""

from __future__ import annotations

import argparse
from itertools import combinations
from pathlib import Path
from typing import Iterable, List

import pandas as pd


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "final" / "final_summary.csv"
DETAIL_COLUMNS = {
    "environment",
    "waf_type",
    "phase",
    "load_level",
    "traffic_type",
    "attack_type",
    "status_code",
    "response_time_ms",
    "blocked_flag",
    "allowed_flag",
    "server_error_flag",
}
ENVIRONMENT_ORDER = ["baseline", "modsec", "coraza", "naxsi"]
DISPLAY_NAMES = {
    "baseline": "Baseline",
    "modsec": "ModSecurity",
    "coraza": "Coraza",
    "naxsi": "NAXSI",
}
ATTACK_SUMMARY_COLUMNS = [
    "environment",
    "waf_type",
    "phase",
    "load_level",
    "attack_type",
    "total_requests",
    "allowed_count",
    "blocked_count",
    "server_error_count",
    "detection_rate_percent",
    "false_negative_rate_percent",
    "avg_response_time_ms",
]
BENIGN_SUMMARY_COLUMNS = [
    "environment",
    "waf_type",
    "phase",
    "load_level",
    "total_benign_requests",
    "benign_allowed",
    "benign_blocked",
    "false_positive_rate_percent",
    "avg_benign_response_time_ms",
]
WAF_COMPARISON_COLUMNS = [
    "phase",
    "load_level",
    "comparison",
    "reference_environment",
    "candidate_environment",
    "detection_rate_difference",
    "false_positive_difference",
    "latency_overhead_ms",
    "latency_overhead_percent",
    "server_error_difference",
]
ENVIRONMENT_SUMMARY_COLUMNS = [
    "environment",
    "waf_type",
    "phase",
    "load_level",
    "detection_rate_percent",
    "false_positive_rate_percent",
    "avg_response_time_ms",
    "server_error_rate_percent",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze detailed WAF evaluation CSV results."
    )
    parser.add_argument(
        "csv_files",
        nargs="*",
        type=Path,
        help="Detailed CSV files or directories containing nested detailed.csv files.",
    )
    parser.add_argument(
        "--input",
        nargs="+",
        type=Path,
        default=None,
        help="Backward-compatible input option for detailed experiment CSV files.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Main final summary CSV path. Named analysis files are written beside it.",
    )
    parser.add_argument(
        "--include-flat-files",
        action="store_true",
        help="Include legacy flat CSV files found directly in input directories.",
    )
    return parser.parse_args()


def resolve_input_paths(paths: Iterable[Path], include_flat_files: bool) -> list[Path]:
    resolved: list[Path] = []
    for path in paths:
        if path.is_file():
            resolved.append(path)
            continue
        if not path.is_dir():
            continue
        nested = sorted(
            candidate
            for candidate in path.rglob("detailed.csv")
            if any(part.startswith("run_") for part in candidate.parts)
        )
        resolved.extend(nested)
        if include_flat_files:
            resolved.extend(sorted(path.glob("*.csv")))
    seen = set()
    unique = []
    for path in resolved:
        key = path.resolve()
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def load_results(paths: Iterable[Path]) -> pd.DataFrame:
    frames: List[pd.DataFrame] = []
    for path in paths:
        if not path.exists() or path.is_dir():
            continue
        frame = pd.read_csv(path)
        if not DETAIL_COLUMNS.issubset(set(frame.columns)):
            continue
        frame["source_file"] = str(path)
        frames.append(frame)
    if not frames:
        raise ValueError("No detailed experiment CSV files were found.")

    data = pd.concat(frames, ignore_index=True)
    if "run_id" not in data.columns:
        data["run_id"] = data["source_file"]
    numeric_columns = [
        "status_code",
        "response_time_ms",
        "blocked_flag",
        "allowed_flag",
        "redirect_flag",
        "client_error_flag",
        "server_error_flag",
        "timeout_flag",
        "zap_alert_count",
        "zap_high_alert_count",
        "zap_medium_alert_count",
        "zap_low_alert_count",
    ]
    for column in numeric_columns:
        if column not in data.columns:
            data[column] = 0
        data[column] = pd.to_numeric(data[column], errors="coerce").fillna(0)
    return data


def build_attack_type_summary(data: pd.DataFrame) -> pd.DataFrame:
    attacks = data[data["traffic_type"] == "attack"].copy()
    rows = []
    group_columns = ["environment", "waf_type", "phase", "load_level", "attack_type"]
    for keys, group in attacks.groupby(group_columns, dropna=False):
        total = len(group)
        allowed = int((group["status_code"] == 200).sum())
        blocked = int(group["blocked_flag"].sum())
        server_errors = int(group["server_error_flag"].sum())
        rows.append(
            {
                "environment": keys[0],
                "waf_type": keys[1],
                "phase": keys[2],
                "load_level": keys[3],
                "attack_type": keys[4],
                "total_requests": total,
                "allowed_count": allowed,
                "blocked_count": blocked,
                "server_error_count": server_errors,
                "detection_rate_percent": percent(blocked, total),
                "false_negative_rate_percent": percent(allowed, total),
                "avg_response_time_ms": round(float(group["response_time_ms"].mean()), 3)
                if total
                else 0.0,
            }
        )
    return pd.DataFrame(rows, columns=ATTACK_SUMMARY_COLUMNS)


def build_benign_summary(data: pd.DataFrame) -> pd.DataFrame:
    benign = data[data["traffic_type"] == "benign"].copy()
    rows = []
    group_columns = ["environment", "waf_type", "phase", "load_level"]
    for keys, group in benign.groupby(group_columns, dropna=False):
        total = len(group)
        allowed = int((group["status_code"] == 200).sum())
        blocked = int(group["blocked_flag"].sum())
        rows.append(
            {
                "environment": keys[0],
                "waf_type": keys[1],
                "phase": keys[2],
                "load_level": keys[3],
                "total_benign_requests": total,
                "benign_allowed": allowed,
                "benign_blocked": blocked,
                "false_positive_rate_percent": percent(blocked, total),
                "avg_benign_response_time_ms": round(
                    float(group["response_time_ms"].mean()), 3
                )
                if total
                else 0.0,
            }
        )
    return pd.DataFrame(rows, columns=BENIGN_SUMMARY_COLUMNS)


def build_waf_comparison(data: pd.DataFrame) -> pd.DataFrame:
    env_metrics = build_environment_metrics(data)
    rows = []
    for (phase, load_level), phase_group in env_metrics.groupby(
        ["phase", "load_level"], dropna=False
    ):
        by_env = {row["environment"]: row for _, row in phase_group.iterrows()}
        for reference, candidate in combinations(ENVIRONMENT_ORDER, 2):
            if reference not in by_env or candidate not in by_env:
                continue
            ref_row = by_env[reference]
            cand_row = by_env[candidate]
            ref_latency = float(ref_row["avg_response_time_ms"])
            cand_latency = float(cand_row["avg_response_time_ms"])
            rows.append(
                {
                    "phase": phase,
                    "load_level": load_level,
                    "comparison": f"{reference}_vs_{candidate}",
                    "reference_environment": reference,
                    "candidate_environment": candidate,
                    "detection_rate_difference": round(
                        cand_row["detection_rate_percent"]
                        - ref_row["detection_rate_percent"],
                        3,
                    ),
                    "false_positive_difference": round(
                        cand_row["false_positive_rate_percent"]
                        - ref_row["false_positive_rate_percent"],
                        3,
                    ),
                    "latency_overhead_ms": round(cand_latency - ref_latency, 3),
                    "latency_overhead_percent": round(
                        ((cand_latency - ref_latency) / ref_latency * 100)
                        if ref_latency
                        else 0.0,
                        3,
                    ),
                    "server_error_difference": round(
                        cand_row["server_error_rate_percent"]
                        - ref_row["server_error_rate_percent"],
                        3,
                    ),
                }
            )
    return pd.DataFrame(rows, columns=WAF_COMPARISON_COLUMNS)


def build_environment_metrics(data: pd.DataFrame) -> pd.DataFrame:
    rows = []
    group_columns = ["environment", "waf_type", "phase", "load_level"]
    for keys, group in data.groupby(group_columns, dropna=False):
        attacks = group[group["traffic_type"] == "attack"]
        benign = group[group["traffic_type"] == "benign"]
        attack_total = len(attacks)
        benign_total = len(benign)
        server_errors = int(group["server_error_flag"].sum())
        rows.append(
            {
                "environment": keys[0],
                "waf_type": keys[1],
                "phase": keys[2],
                "load_level": keys[3],
                "detection_rate_percent": percent(
                    int(attacks["blocked_flag"].sum()), attack_total
                ),
                "false_positive_rate_percent": percent(
                    int(benign["blocked_flag"].sum()), benign_total
                ),
                "avg_response_time_ms": round(
                    float(group["response_time_ms"].mean()), 3
                )
                if len(group)
                else 0.0,
                "server_error_rate_percent": percent(server_errors, len(group)),
            }
        )
    return pd.DataFrame(rows, columns=ENVIRONMENT_SUMMARY_COLUMNS)


def build_repetition_summary(data: pd.DataFrame) -> pd.DataFrame:
    rows = []
    group_columns = ["environment", "waf_type", "phase", "load_level", "run_id"]
    for keys, group in data.groupby(group_columns, dropna=False):
        attacks = group[group["traffic_type"] == "attack"]
        benign = group[group["traffic_type"] == "benign"]
        rows.append(
            {
                "environment": keys[0],
                "waf_type": keys[1],
                "phase": keys[2],
                "load_level": keys[3],
                "run_id": keys[4],
                "total_requests": len(group),
                "attack_requests": len(attacks),
                "benign_requests": len(benign),
                "detection_rate_percent": percent(
                    int(attacks["blocked_flag"].sum()), len(attacks)
                ),
                "false_positive_rate_percent": percent(
                    int(benign["blocked_flag"].sum()), len(benign)
                ),
                "server_error_count": int(group["server_error_flag"].sum()),
                "avg_response_time_ms": round(
                    float(group["response_time_ms"].mean()), 3
                )
                if len(group)
                else 0.0,
            }
        )
    return pd.DataFrame(rows)


def write_report_summary(
    data: pd.DataFrame,
    attack_summary: pd.DataFrame,
    benign_summary: pd.DataFrame,
    output_path: Path,
) -> None:
    lines = [
        "# WAF Evaluation Report Summary",
        "",
        "This summary is based on the authoritative CSV files in `analysis/final/`.",
        "",
        "## Table 1: Attack Counts By Type",
        "",
        markdown_attack_counts(attack_summary),
        "",
        "## Table 2: Detection Rate By Attack Type",
        "",
        markdown_detection_by_type(attack_summary),
        "",
        "## Table 3: False Positive Rate Under Benign Traffic",
        "",
        markdown_false_positive_by_load(benign_summary),
        "",
        "## Table 4: Mixed Traffic Detection Impact",
        "",
        markdown_mixed_detection_impact(data),
        "",
        "Negative detection drop means the mixed-traffic detection rate was slightly higher than the attack-only detection rate in the available run.",
        "",
        "## Table 5: Performance Impact",
        "",
        markdown_performance_impact(data),
        "",
        "## Key Reading Notes",
        "",
        "- Completed automated datasets are available for Baseline, ModSecurity, and Coraza.",
        "- NAXSI structured outputs are not present in this repository.",
        "- Neither ModSecurity nor Coraza blocked benign traffic in the available mixed/setup datasets.",
        "- Logic-style weaknesses such as CSRF, weak session IDs, and authorization bypass were not meaningfully detected by either WAF in the automated data.",
    ]
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_key_findings(
    environment_summary: pd.DataFrame,
    attack_summary: pd.DataFrame,
    benign_summary: pd.DataFrame,
    output_path: Path,
) -> None:
    lines = ["Key Findings", "============", ""]
    if not attack_summary.empty:
        by_env = {
            environment: percent(
                group["blocked_count"].sum(), group["total_requests"].sum()
            )
            for environment, group in attack_summary.groupby(
                "environment", dropna=False
            )
        }
        lines.append("Overall attack detection rate by environment:")
        for environment, value in by_env.items():
            lines.append(f"- {environment}: {value:.2f}%")
        lines.append("")
    if not benign_summary.empty:
        by_env = {
            environment: percent(
                group["benign_blocked"].sum(), group["total_benign_requests"].sum()
            )
            for environment, group in benign_summary.groupby(
                "environment", dropna=False
            )
        }
        lines.append("Overall benign false positive rate by environment:")
        for environment, value in by_env.items():
            lines.append(f"- {environment}: {value:.2f}%")
        lines.append("")
    if not environment_summary.empty:
        worst = environment_summary.sort_values(
            "server_error_rate_percent", ascending=False
        ).head(1)
        row = worst.iloc[0]
        lines.append(
            "Highest observed server-error rate: "
            f"{row['environment']} {row['phase']} {row['load_level']} "
            f"({row['server_error_rate_percent']:.2f}%)."
        )
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def markdown_attack_counts(attack_summary: pd.DataFrame) -> str:
    headers = ["Attack Type", "Baseline Sent", "ModSecurity Sent", "Coraza Sent", "NAXSI Sent"]
    rows = []
    for attack_type in sorted(attack_summary["attack_type"].dropna().unique()):
        row = [attack_type]
        for env in ENVIRONMENT_ORDER:
            total = attack_summary[
                (attack_summary["environment"] == env)
                & (attack_summary["attack_type"] == attack_type)
            ]["total_requests"].sum()
            row.append(str(int(total)))
        rows.append(row)
    return markdown_table(headers, rows)


def markdown_detection_by_type(attack_summary: pd.DataFrame) -> str:
    headers = ["Attack Type", "ModSecurity", "Coraza", "NAXSI"]
    rows = []
    for attack_type in sorted(attack_summary["attack_type"].dropna().unique()):
        row = [attack_type]
        for env in ["modsec", "coraza", "naxsi"]:
            group = attack_summary[
                (attack_summary["environment"] == env)
                & (attack_summary["attack_type"] == attack_type)
            ]
            blocked = group["blocked_count"].sum()
            total = group["total_requests"].sum()
            row.append(f"{percent(blocked, total):.2f}%" if total else "No data")
        rows.append(row)
    return markdown_table(headers, rows)


def markdown_false_positive_by_load(benign_summary: pd.DataFrame) -> str:
    headers = ["Dataset", "Baseline", "ModSecurity", "Coraza", "NAXSI"]
    rows = []
    datasets = (
        benign_summary[["phase", "load_level"]]
        .drop_duplicates()
        .sort_values(["phase", "load_level"])
    )
    for _, dataset in datasets.iterrows():
        phase = dataset["phase"]
        load_level = dataset["load_level"]
        row = [f"{phase} / {load_level}"]
        for env in ENVIRONMENT_ORDER:
            group = benign_summary[
                (benign_summary["environment"] == env)
                & (benign_summary["phase"] == phase)
                & (benign_summary["load_level"] == load_level)
            ]
            blocked = group["benign_blocked"].sum()
            total = group["total_benign_requests"].sum()
            row.append(f"{percent(blocked, total):.2f}%" if total else "No data")
        rows.append(row)
    return markdown_table(headers, rows)


def markdown_mixed_detection_impact(data: pd.DataFrame) -> str:
    headers = ["WAF", "Attack-Only Detection", "Mixed Detection", "Detection Drop"]
    rows = []
    for env in ["modsec", "coraza", "naxsi"]:
        attack_only = detection_for(data, env, "attack_only")
        mixed = detection_for(data, env, "mixed")
        if attack_only is None or mixed is None:
            rows.append([DISPLAY_NAMES[env], "No data", "No data", "No data"])
        else:
            rows.append(
                [
                    DISPLAY_NAMES[env],
                    f"{attack_only:.2f}%",
                    f"{mixed:.2f}%",
                    f"{attack_only - mixed:.2f}%",
                ]
            )
    return markdown_table(headers, rows)


def markdown_performance_impact(data: pd.DataFrame) -> str:
    headers = [
        "WAF",
        "Attack-Only Avg Latency",
        "Attack-Only Over Baseline",
        "Mixed Avg Latency",
        "Mixed Over Baseline",
    ]
    rows = []
    baseline_attack = latency_for(data, "baseline", "attack_only", "none")
    baseline_mixed = latency_for(data, "baseline", "mixed", "medium")
    for env in ENVIRONMENT_ORDER:
        attack = latency_for(data, env, "attack_only", "none")
        mixed = latency_for(data, env, "mixed", "medium")
        if attack is None or mixed is None:
            rows.append([DISPLAY_NAMES[env], "No data", "No data", "No data", "No data"])
            continue
        attack = round(attack, 3)
        mixed = round(mixed, 3)
        attack_baseline = round(baseline_attack, 3)
        mixed_baseline = round(baseline_mixed, 3)
        rows.append(
            [
                DISPLAY_NAMES[env],
                f"{attack:.3f} ms",
                f"{attack - attack_baseline:.3f} ms",
                f"{mixed:.3f} ms",
                f"{mixed - mixed_baseline:.3f} ms",
            ]
        )
    return markdown_table(headers, rows)


def detection_for(data: pd.DataFrame, environment: str, phase: str) -> float | None:
    group = data[(data["environment"] == environment) & (data["phase"] == phase)]
    attacks = group[group["traffic_type"] == "attack"]
    if attacks.empty:
        return None
    return percent(int(attacks["blocked_flag"].sum()), len(attacks))


def latency_for(
    data: pd.DataFrame, environment: str, phase: str, load_level: str
) -> float | None:
    group = data[
        (data["environment"] == environment)
        & (data["phase"] == phase)
        & (data["load_level"] == load_level)
    ]
    if group.empty:
        return None
    return float(group["response_time_ms"].mean())


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        rows = [["0" for _ in headers]]
    header_line = "| " + " | ".join(headers) + " |"
    separator = "| " + " | ".join(["---", *(["---:"] * (len(headers) - 1))]) + " |"
    row_lines = ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join([header_line, separator, *row_lines])


def percent(numerator: int | float, denominator: int | float) -> float:
    if denominator == 0:
        return 0.0
    return round(float(numerator) / float(denominator) * 100, 3)


def main() -> int:
    args = parse_args()
    requested_paths = args.input if args.input is not None else args.csv_files
    if not requested_paths:
        raise SystemExit("Provide one or more detailed experiment CSV files.")

    input_paths = resolve_input_paths(requested_paths, args.include_flat_files)
    if not input_paths:
        raise SystemExit("No nested detailed.csv files were found.")

    data = load_results(input_paths)
    attack_summary = build_attack_type_summary(data)
    benign_summary = build_benign_summary(data)
    waf_comparison = build_waf_comparison(data)
    environment_summary = build_environment_metrics(data)
    repetition_summary = build_repetition_summary(data)

    output_dir = args.out.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    environment_summary.to_csv(args.out, index=False)
    attack_summary.to_csv(
        output_dir / "final_attack_type_summary.csv",
        index=False,
        float_format=lambda value: f"{value:g}",
        lineterminator="\n",
    )
    benign_summary.to_csv(output_dir / "final_benign_summary.csv", index=False)
    waf_comparison.to_csv(output_dir / "final_waf_comparison.csv", index=False)
    repetition_summary.to_csv(
        output_dir / "final_repetition_summary.csv", index=False
    )
    write_report_summary(
        data,
        attack_summary,
        benign_summary,
        output_dir / "report_summary.md",
    )
    write_key_findings(
        environment_summary,
        attack_summary,
        benign_summary,
        output_dir / "key_findings.txt",
    )

    print(f"Final summary written to {args.out}")
    print(f"Attack type summary written to {output_dir / 'final_attack_type_summary.csv'}")
    print(f"Benign summary written to {output_dir / 'final_benign_summary.csv'}")
    print(f"WAF comparison written to {output_dir / 'final_waf_comparison.csv'}")
    print(f"Repetition summary written to {output_dir / 'final_repetition_summary.csv'}")
    print(f"Report summary written to {output_dir / 'report_summary.md'}")
    print(f"Key findings written to {output_dir / 'key_findings.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
