"""Per-run summary outputs for WAF experiments."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, Iterable, Tuple

from config import ATTACK_TYPES, EnvironmentConfig


SUMMARY_COLUMNS = [
    "run_id",
    "environment",
    "waf_type",
    "phase",
    "load_level",
    "traffic_type",
    "attack_type",
    "total_requests",
    "allowed_count",
    "blocked_count",
    "redirect_count",
    "client_error_count",
    "server_error_count",
    "timeout_count",
    "success_count",
    "failed_count",
    "detection_rate_percent",
    "false_negative_rate_percent",
    "false_positive_rate_percent",
    "avg_response_time_ms",
    "min_response_time_ms",
    "max_response_time_ms",
]


def write_run_outputs(
    rows: Iterable[dict],
    output_file: Path,
    run_id: str,
    environment: EnvironmentConfig,
    phase: str,
    load_level: str,
    duration_seconds: int,
) -> Tuple[Path, Path, dict]:
    filtered_rows = [
        row
        for row in rows
        if row.get("phase") == phase and row.get("load_level") == load_level
    ]
    output_dir = Path(output_file).parent
    summary_path = output_dir / "summary.csv"
    json_path = output_dir / "run_summary.json"

    summary_rows = build_summary_rows(
        filtered_rows, run_id, environment, phase, load_level
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUMMARY_COLUMNS)
        writer.writeheader()
        writer.writerows(summary_rows)

    run_summary = build_run_summary(
        filtered_rows, run_id, environment, phase, load_level, duration_seconds
    )
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(run_summary, handle, indent=2)
        handle.write("\n")

    return summary_path, json_path, run_summary


def build_summary_rows(
    rows: list[dict],
    run_id: str,
    environment: EnvironmentConfig,
    phase: str,
    load_level: str,
) -> list[dict]:
    groups: Dict[tuple, list[dict]] = {}
    for row in rows:
        key = (row.get("traffic_type", ""), row.get("attack_type", ""))
        groups.setdefault(key, []).append(row)

    summary_rows = []
    for (traffic_type, attack_type), group in sorted(groups.items()):
        summary_rows.append(
            build_summary_row(
                group,
                run_id,
                environment,
                phase,
                load_level,
                traffic_type,
                attack_type,
            )
        )
    return summary_rows


def build_summary_row(
    group: list[dict],
    run_id: str,
    environment: EnvironmentConfig,
    phase: str,
    load_level: str,
    traffic_type: str,
    attack_type: str,
) -> dict:
    total_requests = len(group)
    allowed_count = count_status(group, {200})
    blocked_count = sum_int(group, "blocked_flag")
    redirect_count = sum_int(group, "redirect_flag")
    client_error_count = sum_int(group, "client_error_flag")
    server_error_count = sum_int(group, "server_error_flag")
    timeout_count = sum_int(group, "timeout_flag")

    if traffic_type == "attack":
        success_count = count_successful_attacks(group)
        detection_rate = percent(blocked_count, total_requests)
        false_negative_rate = percent(allowed_count, total_requests)
        false_positive_rate = 0.0
    else:
        success_count = allowed_count + redirect_count
        detection_rate = 0.0
        false_negative_rate = 0.0
        false_positive_rate = percent(blocked_count, total_requests)

    response_times = [float_or_zero(row.get("response_time_ms")) for row in group]
    avg_response = sum(response_times) / len(response_times) if response_times else 0.0

    return {
        "run_id": run_id,
        "environment": environment.name,
        "waf_type": environment.waf_type,
        "phase": phase,
        "load_level": load_level,
        "traffic_type": traffic_type,
        "attack_type": attack_type,
        "total_requests": total_requests,
        "allowed_count": allowed_count,
        "blocked_count": blocked_count,
        "redirect_count": redirect_count,
        "client_error_count": client_error_count,
        "server_error_count": server_error_count,
        "timeout_count": timeout_count,
        "success_count": success_count,
        "failed_count": total_requests - success_count,
        "detection_rate_percent": round(detection_rate, 3),
        "false_negative_rate_percent": round(false_negative_rate, 3),
        "false_positive_rate_percent": round(false_positive_rate, 3),
        "avg_response_time_ms": round(avg_response, 3),
        "min_response_time_ms": round(min(response_times), 3) if response_times else 0,
        "max_response_time_ms": round(max(response_times), 3) if response_times else 0,
    }


def build_run_summary(
    rows: list[dict],
    run_id: str,
    environment: EnvironmentConfig,
    phase: str,
    load_level: str,
    duration_seconds: int,
) -> dict:
    attack_rows = [row for row in rows if row.get("traffic_type") == "attack"]
    benign_rows = [row for row in rows if row.get("traffic_type") == "benign"]

    attacks_by_type = {}
    for attack_type in ATTACK_TYPES:
        group = [row for row in attack_rows if row.get("attack_type") == attack_type]
        sent = len(group)
        blocked = sum_int(group, "blocked_flag")
        allowed = count_status(group, {200})
        server_errors = sum_int(group, "server_error_flag")
        attacks_by_type[attack_type] = {
            "sent": sent,
            "allowed": allowed,
            "blocked": blocked,
            "server_errors": server_errors,
            "detection_rate_percent": round(percent(blocked, sent), 3),
        }

    benign_sent = len(benign_rows)
    benign_allowed = count_status(benign_rows, {200})
    benign_blocked = sum_int(benign_rows, "blocked_flag")
    benign_times = [float_or_zero(row.get("response_time_ms")) for row in benign_rows]
    avg_benign = sum(benign_times) / len(benign_times) if benign_times else 0.0

    return {
        "run_id": run_id,
        "environment": environment.name,
        "waf_type": environment.waf_type,
        "phase": phase,
        "load_level": load_level,
        "duration_seconds": duration_seconds,
        "total_requests": len(rows),
        "total_attack_requests": len(attack_rows),
        "total_benign_requests": benign_sent,
        "attacks_by_type": attacks_by_type,
        "benign_traffic": {
            "sent": benign_sent,
            "allowed": benign_allowed,
            "blocked": benign_blocked,
            "false_positive_rate_percent": round(percent(benign_blocked, benign_sent), 3),
            "avg_response_time_ms": round(avg_benign, 3),
        },
    }


def print_console_summary(run_summary: dict) -> None:
    print("Attack summary:")
    for attack_type in ATTACK_TYPES:
        metrics = run_summary["attacks_by_type"][attack_type]
        print(
            f"  {attack_type} sent: {metrics['sent']}, "
            f"blocked: {metrics['blocked']}, allowed: {metrics['allowed']}"
        )
    benign = run_summary["benign_traffic"]
    print("Benign traffic:")
    print(
        f"  sent: {benign['sent']}, blocked: {benign['blocked']}, "
        f"false positive rate: {benign['false_positive_rate_percent']}%"
    )


def count_status(rows: list[dict], statuses: set[int]) -> int:
    return sum(1 for row in rows if int_or_zero(row.get("status_code")) in statuses)


def count_successful_attacks(rows: list[dict]) -> int:
    return sum(
        1
        for row in rows
        if int_or_zero(row.get("status_code")) == 200
        and row.get("expected_behavior") == "blocked"
    )


def sum_int(rows: list[dict], column: str) -> int:
    return sum(int_or_zero(row.get(column)) for row in rows)


def int_or_zero(value) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def float_or_zero(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def percent(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator * 100
