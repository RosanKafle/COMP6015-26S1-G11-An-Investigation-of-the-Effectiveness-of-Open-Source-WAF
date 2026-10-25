#!/usr/bin/env python3

import csv
import subprocess
from io import StringIO
from pathlib import Path


BRANCH = "origin/main"

OUTPUT_DIR = Path(__file__).resolve().parents[1] / "results/validation"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def load_csv(path):
    result = subprocess.run(
        ["git", "show", f"{BRANCH}:{path}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return list(csv.DictReader(StringIO(result.stdout)))


def pct(numerator, denominator):
    if denominator == 0:
        return 0.0
    return numerator / denominator * 100


def close(a, b, tolerance=0.01):
    return abs(float(a) - float(b)) <= tolerance


def write_csv(filename, rows):
    output = OUTPUT_DIR / filename

    if not rows:
        return output

    with output.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=rows[0].keys()
        )
        writer.writeheader()
        writer.writerows(rows)

    return output


print("=" * 70)
print("WAF RESULTS INDEPENDENT VALIDATION")
print("=" * 70)
print(f"Source branch: {BRANCH}")
print()


# ============================================================
# 1. ATTACK-TYPE VALIDATION
# ============================================================

attack_rows = load_csv(
    "analysis/final/final_attack_type_summary.csv"
)

attack_validation = []

for row in attack_rows:

    total = int(row["total_requests"])
    allowed = int(row["allowed_count"])
    blocked = int(row["blocked_count"])
    errors = int(row["server_error_count"])

    calculated_detection = pct(blocked, total)
    calculated_false_negative = pct(allowed, total)

    count_check = (
        total == allowed + blocked + errors
    )

    detection_check = close(
        calculated_detection,
        float(row["detection_rate_percent"])
    )

    false_negative_check = close(
        calculated_false_negative,
        float(row["false_negative_rate_percent"])
    )

    overall = (
        count_check
        and detection_check
        and false_negative_check
    )

    attack_validation.append({
        "environment": row["environment"],
        "phase": row["phase"],
        "load_level": row["load_level"],
        "attack_type": row["attack_type"],
        "total_requests": total,
        "allowed": allowed,
        "blocked": blocked,
        "server_errors": errors,
        "reported_detection_percent":
            row["detection_rate_percent"],
        "calculated_detection_percent":
            round(calculated_detection, 3),
        "reported_false_negative_percent":
            row["false_negative_rate_percent"],
        "calculated_false_negative_percent":
            round(calculated_false_negative, 3),
        "count_check":
            "PASS" if count_check else "FAIL",
        "detection_check":
            "PASS" if detection_check else "FAIL",
        "false_negative_check":
            "PASS" if false_negative_check else "FAIL",
        "overall_check":
            "PASS" if overall else "FAIL",
    })


attack_output = write_csv(
    "attack_type_validation.csv",
    attack_validation,
)

print(f"[1] Attack-type validation: {attack_output}")


# ============================================================
# 2. BENIGN / FALSE-POSITIVE VALIDATION
#
# Setup records are deliberately excluded because they are
# environment/setup traffic rather than normal benign traffic.
# ============================================================

benign_rows = load_csv(
    "analysis/final/final_benign_summary.csv"
)

benign_validation = []

for row in benign_rows:

    environment = row["environment"]
    phase = row["phase"]

    if phase == "setup":
        benign_validation.append({
            "environment": environment,
            "phase": phase,
            "load_level": row["load_level"],
            "total_benign_requests":
                row["total_benign_requests"],
            "allowed":
                row["benign_allowed"],
            "blocked":
                row["benign_blocked"],
            "reported_fp_percent":
                row["false_positive_rate_percent"],
            "calculated_fp_percent":
                "N/A",
            "count_check":
                "EXCLUDED",
            "fp_check":
                "EXCLUDED",
            "overall_check":
                "EXCLUDED_SETUP",
        })
        continue

    total = int(row["total_benign_requests"])
    allowed = int(row["benign_allowed"])
    blocked = int(row["benign_blocked"])

    calculated_fp = pct(blocked, total)

    count_check = (
        total == allowed + blocked
    )

    fp_check = close(
        calculated_fp,
        float(row["false_positive_rate_percent"])
    )

    benign_validation.append({
        "environment": environment,
        "phase": phase,
        "load_level": row["load_level"],
        "total_benign_requests": total,
        "allowed": allowed,
        "blocked": blocked,
        "reported_fp_percent":
            row["false_positive_rate_percent"],
        "calculated_fp_percent":
            round(calculated_fp, 3),
        "count_check":
            "PASS" if count_check else "FAIL",
        "fp_check":
            "PASS" if fp_check else "FAIL",
        "overall_check":
            "PASS" if count_check and fp_check else "FAIL",
    })


benign_output = write_csv(
    "benign_validation.csv",
    benign_validation,
)

print(f"[2] Benign/false-positive validation: {benign_output}")


# ============================================================
# 3. REPETITION VALIDATION
# ============================================================

repetition_rows = load_csv(
    "analysis/final/final_repetition_summary.csv"
)

repetition_validation = []

for row in repetition_rows:

    total = int(row["total_requests"])
    attacks = int(row["attack_requests"])
    benign = int(row["benign_requests"])

    total_check = (
        total == attacks + benign
    )

    repetition_validation.append({
        "environment": row["environment"],
        "phase": row["phase"],
        "load_level": row["load_level"],
        "run_id": row["run_id"],
        "total_requests": total,
        "attack_requests": attacks,
        "benign_requests": benign,
        "reported_detection_percent":
            row["detection_rate_percent"],
        "reported_fp_percent":
            row["false_positive_rate_percent"],
        "server_errors":
            row["server_error_count"],
        "total_check":
            "PASS" if total_check else "FAIL",
    })


repetition_output = write_csv(
    "repetition_validation.csv",
    repetition_validation,
)

print(f"[3] Repetition validation: {repetition_output}")


# ============================================================
# 4. FINAL SUMMARY VALIDATION
#
# Detection is validated against attack requests.
#
# Server-error rate uses:
#   - attack population for attack-only
#   - complete mixed population for mixed
#
# This follows the project's phase-specific reporting method.
# ============================================================

final_rows = load_csv(
    "analysis/final/final_summary.csv"
)

summary_validation = []

for final in final_rows:

    environment = final["environment"]
    phase = final["phase"]
    load_level = final["load_level"]

    matching_runs = [
        r for r in repetition_rows
        if r["environment"] == environment
        and r["phase"] == phase
        and r["load_level"] == load_level
    ]

    if matching_runs:

        # There is normally one authoritative run for each
        # environment/phase/load combination.
        run = matching_runs[0]

        total_requests = int(run["total_requests"])
        attack_requests = int(run["attack_requests"])
        server_errors = int(run["server_error_count"])

        if phase == "mixed":
            error_denominator = total_requests
        else:
            error_denominator = attack_requests

        calculated_error_rate = pct(
            server_errors,
            error_denominator
        )

        reported_error_rate = float(
            final["server_error_rate_percent"]
        )

        error_check = close(
            calculated_error_rate,
            reported_error_rate
        )

        detection_check = close(
            float(final["detection_rate_percent"]),
            float(run["detection_rate_percent"])
        )

        summary_validation.append({
            "environment": environment,
            "phase": phase,
            "load_level": load_level,
            "reported_detection_percent":
                final["detection_rate_percent"],
            "repetition_detection_percent":
                run["detection_rate_percent"],
            "detection_check":
                "PASS" if detection_check else "FAIL",
            "server_errors":
                server_errors,
            "error_denominator":
                error_denominator,
            "reported_error_percent":
                final["server_error_rate_percent"],
            "calculated_error_percent":
                round(calculated_error_rate, 3),
            "error_check":
                "PASS" if error_check else "FAIL",
            "overall_check":
                "PASS"
                if detection_check and error_check
                else "FAIL",
        })


summary_output = write_csv(
    "final_summary_validation.csv",
    summary_validation,
)

print(f"[4] Final-summary validation: {summary_output}")


# ============================================================
# 5. MISSED ATTACK INVENTORY
# ============================================================

missed_rows = load_csv(
    "analysis/final/missed_attacks.csv"
)

missed_summary = {}

for row in missed_rows:

    key = (
        row["environment"],
        row["phase"],
        row["load_level"],
        row["attack_type"],
    )

    if key not in missed_summary:
        missed_summary[key] = {
            "total_missed_records": 0,
            "allowed": 0,
            "server_errors": 0,
        }

    missed_summary[key]["total_missed_records"] += 1

    if row["result"] == "allowed":
        missed_summary[key]["allowed"] += 1

    elif row["result"] == "server_error":
        missed_summary[key]["server_errors"] += 1


missed_validation = []

for key, values in sorted(missed_summary.items()):

    environment, phase, load_level, attack_type = key

    missed_validation.append({
        "environment": environment,
        "phase": phase,
        "load_level": load_level,
        "attack_type": attack_type,
        "total_missed_records":
            values["total_missed_records"],
        "allowed":
            values["allowed"],
        "server_errors":
            values["server_errors"],
    })


missed_output = write_csv(
    "missed_attack_validation.csv",
    missed_validation,
)

print(f"[5] Missed-attack validation: {missed_output}")


# ============================================================
# 6. OVERALL RESULT
# ============================================================

all_checks = []

for row in attack_validation:
    all_checks.append(row["overall_check"])

for row in benign_validation:
    if row["overall_check"] != "EXCLUDED_SETUP":
        all_checks.append(row["overall_check"])

for row in repetition_validation:
    all_checks.append(row["total_check"])

for row in summary_validation:
    all_checks.append(row["overall_check"])


passed = all_checks.count("PASS")
failed = all_checks.count("FAIL")

print()
print("=" * 70)
print("VALIDATION RESULT")
print("=" * 70)
print(f"Checks passed : {passed}")
print(f"Checks failed : {failed}")
print(f"Checks tested : {len(all_checks)}")
print("Setup benign rows: excluded from normal FP validation")

if failed == 0:
    print("RESULT: PASS - reported metrics are internally consistent.")
else:
    print("RESULT: REVIEW - one or more metrics require inspection.")

print()
print("Original project files were read from Git only.")
print("No existing project files were modified.")
print(f"Generated validation files are under {OUTPUT_DIR}/")
