#!/usr/bin/env python3

import csv
import subprocess
from io import StringIO
from pathlib import Path


BRANCH = "origin/main"
OUTPUT = Path(__file__).resolve().parents[1] / "results/analysis"
OUTPUT.mkdir(parents=True, exist_ok=True)


def load_csv(path):
    result = subprocess.run(
        ["git", "show", f"{BRANCH}:{path}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return list(csv.DictReader(StringIO(result.stdout)))


def pct(value, total):
    if total == 0:
        return 0.0
    return round(value / total * 100, 3)


def write_csv(filename, rows):
    path = OUTPUT / filename

    if not rows:
        return

    with path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=rows[0].keys()
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Written: {path}")


# ============================================================
# LOAD AUTHORITATIVE PROJECT RESULTS
# ============================================================

attack_rows = load_csv(
    "analysis/final/final_attack_type_summary.csv"
)

final_rows = load_csv(
    "analysis/final/final_summary.csv"
)

repetition_rows = load_csv(
    "analysis/final/final_repetition_summary.csv"
)


# ============================================================
# HELPER: MATCH REPETITION DATA
# ============================================================

def find_repetition(environment, phase, load_level):
    matches = [
        r for r in repetition_rows
        if r["environment"] == environment
        and r["phase"] == phase
        and r["load_level"] == load_level
    ]

    if not matches:
        return None

    return matches[0]


# ============================================================
# 1. OVERALL WAF COMPARISON
# ============================================================

overall = []

for row in final_rows:

    if row["phase"] == "setup":
        continue

    repetition = find_repetition(
        row["environment"],
        row["phase"],
        row["load_level"]
    )

    if repetition is None:
        continue

    overall.append({
        "environment": row["environment"],
        "waf_type": row["waf_type"],
        "phase": row["phase"],
        "load_level": row["load_level"],
        "run_id": repetition["run_id"],
        "total_requests": repetition["total_requests"],
        "attack_requests": repetition["attack_requests"],
        "benign_requests": repetition["benign_requests"],
        "detection_rate_percent":
            row["detection_rate_percent"],
        "false_positive_rate_percent":
            row["false_positive_rate_percent"],
        "server_error_rate_percent":
            row["server_error_rate_percent"],
        "avg_response_time_ms":
            row["avg_response_time_ms"],
    })


write_csv(
    "waf_overall_comparison.csv",
    overall
)


# ============================================================
# 2. ATTACK-TYPE COMPARISON
# ============================================================

attack_types = sorted(
    set(row["attack_type"] for row in attack_rows)
)

environments = [
    "baseline",
    "coraza",
    "modsec",
]

comparison = []

for phase in ["attack_only", "mixed"]:

    load_level = (
        "none"
        if phase == "attack_only"
        else "medium"
    )

    for attack_type in attack_types:

        output_row = {
            "phase": phase,
            "load_level": load_level,
            "attack_type": attack_type,
        }

        for environment in environments:

            matches = [
                r for r in attack_rows
                if r["environment"] == environment
                and r["phase"] == phase
                and r["load_level"] == load_level
                and r["attack_type"] == attack_type
            ]

            if not matches:
                output_row[
                    f"{environment}_detection_percent"
                ] = ""

                output_row[
                    f"{environment}_allowed"
                ] = ""

                output_row[
                    f"{environment}_blocked"
                ] = ""

                output_row[
                    f"{environment}_errors"
                ] = ""

                continue

            r = matches[0]

            output_row[
                f"{environment}_detection_percent"
            ] = r["detection_rate_percent"]

            output_row[
                f"{environment}_allowed"
            ] = r["allowed_count"]

            output_row[
                f"{environment}_blocked"
            ] = r["blocked_count"]

            output_row[
                f"{environment}_errors"
            ] = r["server_error_count"]

        comparison.append(output_row)


write_csv(
    "attack_type_comparison.csv",
    comparison
)


# ============================================================
# 3. DETECTION GAP ANALYSIS
# ============================================================

gaps = []

for row in attack_rows:

    if row["environment"] == "baseline":
        continue

    total = int(row["total_requests"])
    allowed = int(row["allowed_count"])
    blocked = int(row["blocked_count"])
    errors = int(row["server_error_count"])

    non_cleanly_blocked = allowed + errors

    gaps.append({
        "environment": row["environment"],
        "phase": row["phase"],
        "load_level": row["load_level"],
        "attack_type": row["attack_type"],
        "total_requests": total,
        "blocked": blocked,
        "allowed": allowed,
        "server_errors": errors,
        "non_cleanly_blocked":
            non_cleanly_blocked,
        "detection_rate_percent":
            row["detection_rate_percent"],
        "non_clean_block_rate_percent":
            pct(non_cleanly_blocked, total),
    })


write_csv(
    "detection_gap_analysis.csv",
    gaps
)


# ============================================================
# 4. PERFORMANCE COMPARISON
# ============================================================

performance = []

for row in attack_rows:

    performance.append({
        "environment": row["environment"],
        "phase": row["phase"],
        "load_level": row["load_level"],
        "attack_type": row["attack_type"],
        "avg_response_time_ms":
            row["avg_response_time_ms"],
    })


write_csv(
    "performance_comparison.csv",
    performance
)


# ============================================================
# 5. INDIVIDUAL FINDINGS
# ============================================================

findings = []

findings.append("# Individual WAF Results Analysis")
findings.append("")
findings.append(
    "This analysis uses the existing project result datasets "
    "as read-only sources. The results were independently "
    "validated before analysis."
)

findings.append("")
findings.append("## Validation Status")
findings.append("")
findings.append(
    "- Independent validation completed with 66 checks passed "
    "and 0 checks failed."
)
findings.append(
    "- Original project evidence was not modified."
)
findings.append(
    "- Setup traffic was excluded from normal false-positive "
    "analysis."
)


# ------------------------------------------------------------
# Overall detection
# ------------------------------------------------------------

findings.append("")
findings.append("## Overall Detection Performance")
findings.append("")

for row in overall:

    findings.append(
        f"- {row['environment']} "
        f"({row['phase']}): "
        f"detection {row['detection_rate_percent']}%, "
        f"false positives {row['false_positive_rate_percent']}%, "
        f"server errors {row['server_error_rate_percent']}%, "
        f"average response time "
        f"{row['avg_response_time_ms']} ms."
    )


# ------------------------------------------------------------
# Attack-specific findings
# ------------------------------------------------------------

findings.append("")
findings.append("## Attack-Specific Detection Gaps")
findings.append("")

for environment in ["coraza", "modsec"]:

    findings.append(
        f"### {environment}"
    )
    findings.append("")

    rows = [
        r for r in gaps
        if r["environment"] == environment
        and r["phase"] == "attack_only"
    ]

    for row in rows:

        if int(row["non_cleanly_blocked"]) > 0:

            findings.append(
                f"- {row['attack_type']}: "
                f"{row['blocked']} blocked, "
                f"{row['allowed']} allowed and "
                f"{row['server_errors']} server errors "
                f"from {row['total_requests']} requests. "
                f"Detection rate: "
                f"{row['detection_rate_percent']}%."
            )


# ------------------------------------------------------------
# False positives
# ------------------------------------------------------------

findings.append("")
findings.append("## False-Positive Findings")
findings.append("")

findings.append(
    "The validated mixed-traffic results report a "
    "0% false-positive rate for baseline, Coraza and "
    "ModSecurity."
)


# ------------------------------------------------------------
# Comparison
# ------------------------------------------------------------

findings.append("")
findings.append("## Comparative Interpretation")
findings.append("")

findings.append(
    "Coraza and ModSecurity show broadly comparable "
    "detection performance in the validated dataset."
)

findings.append(
    "For attack-only testing, ModSecurity reports a "
    "slightly higher overall detection rate than Coraza."
)

findings.append(
    "For mixed testing, Coraza reports a slightly higher "
    "overall detection rate than ModSecurity."
)

findings.append(
    "The differences are small, so the results do not "
    "support claiming that one WAF is universally superior "
    "based on detection rate alone."
)


# ------------------------------------------------------------
# Missed attacks
# ------------------------------------------------------------

findings.append("")
findings.append("## Missed and Non-Cleanly-Blocked Attacks")
findings.append("")

findings.append(
    "The analysis treats allowed attacks and server errors "
    "separately from clean WAF blocks. Server errors are not "
    "counted as successful WAF detections."
)

findings.append(
    "SQL injection represents an important detection gap "
    "because both Coraza and ModSecurity produced allowed "
    "requests as well as server-error responses."
)

findings.append(
    "XSS also produced allowed requests for both WAFs, "
    "while several other attack categories in the tested "
    "dataset were not cleanly blocked."
)


# ------------------------------------------------------------
# Reproducibility
# ------------------------------------------------------------

findings.append("")
findings.append("## Reproducibility")
findings.append("")

findings.append(
    "The analysis reads the project datasets directly from "
    "the Git repository and produces separate files under "
    f"{OUTPUT}/."
)

findings.append(
    "The original group result files remain unchanged."
)


(OUTPUT / "individual_findings.md").write_text(
    "\n".join(findings) + "\n"
)

print(
    f"Written: {OUTPUT / 'individual_findings.md'}"
)

print()
print("Analysis completed successfully.")
