"""Generate a report from actual supplied results, with unknowns and limits visible."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
from category_summary import summarize
from metrics import calculate, one_condition, read_results
from result_writer import sha256

def display(value) -> str:
    return "N/A (no classified denominator)" if value is None else str(value)

def safe(value: str) -> str:
    return value.replace("|", r"\|").replace("\n", " ").replace("\r", " ").replace("<", "&lt;").replace(">", "&gt;")

def paired(rows: list[dict]) -> dict:
    baseline = {r["test_id"]: r for r in rows if not r["parent_test_id"]}
    result = {"candidate_rows": 0, "classified_pairs": 0, "blocked_to_allowed": 0,
              "allowed_to_blocked": 0, "unchanged": 0, "unpaired_or_unknown": 0}
    for row in rows:
        if not row["parent_test_id"]:
            continue
        result["candidate_rows"] += 1
        parent = baseline.get(row["parent_test_id"])
        if not parent or row["waf_action"] == "UNKNOWN" or parent["waf_action"] == "UNKNOWN":
            result["unpaired_or_unknown"] += 1
            continue
        if row["expected_class"] != parent["expected_class"] or row["category"] != parent["category"]:
            raise ValueError("Variant parent has incompatible traffic labels.")
        result["classified_pairs"] += 1
        if parent["waf_action"] == row["waf_action"]:
            result["unchanged"] += 1
        elif parent["waf_action"] == "BLOCKED":
            result["blocked_to_allowed"] += 1
        else:
            result["allowed_to_blocked"] += 1
    return result

def generate(source: Path | None, output: Path) -> None:
    rows = read_results(source)
    one_condition(rows)
    metrics = calculate(rows)
    categories = summarize(rows)
    pairs = paired(rows)
    normal = [r for r in rows if r["expected_class"] == "NORMAL"]
    malicious = [r for r in rows if r["expected_class"] == "MALICIOUS"]
    lines = [
        "# Initial analysis", "",
        "## 1. Experiment information", "",
        f"- Run: {safe(rows[0]['run_id'])}",
        f"- WAF: {safe(rows[0]['waf'])}",
        f"- Source: {safe(str(source.resolve()))}",
        f"- Source SHA-256: {sha256(source.read_bytes())}",
        f"- Test-set SHA-256: {safe(rows[0]['test_set_sha256'])}",
        f"- Collection timestamps: {min(r['timestamp'] for r in rows)} to {max(r['timestamp'] for r in rows)}",
        f"- Report generated: {datetime.now(timezone.utc).isoformat()}", "",
        "## 2. Number of tests", "",
        f"Rows: {len(rows)}; HTTP responses: {metrics['sent']}; errors: {metrics['errors']}; skipped: {metrics['skipped']}.",
        f"Unclassified rows: {metrics['UNKNOWN']}. Skipped rows are not executed trials.", "",
        "## 3. Normal traffic", "",
        f"Rows: {len(normal)}; TN: {metrics['TN']}; FP: {metrics['FP']}.",
        f"False-positive rate: {display(metrics['false_positive_rate'])}.",
        f"Normal allow rate: {display(metrics['normal_allow_rate'])}.", "",
        "## 4. Malicious traffic", "",
        f"Rows: {len(malicious)}; TP: {metrics['TP']}; FN: {metrics['FN']}.",
        f"Detection rate: {display(metrics['detection_rate'])}.",
        f"False-negative rate: {display(metrics['false_negative_rate'])}.", "",
        "## 5. Overall confusion matrix", "",
        "| Expected | BLOCKED | ALLOWED |",
        "|---|---:|---:|",
        f"| MALICIOUS | {metrics['TP']} | {metrics['FN']} |",
        f"| NORMAL | {metrics['FP']} | {metrics['TN']} |", "",
        f"UNKNOWN ({metrics['UNKNOWN']}) is excluded from matrix rates, not converted to FN/TN.", "",
        "## 6. Per-category detection", "",
        "| Category | HTTP responses | Blocked | Allowed | Unknown responses | Errors | Skipped | Detection rate |",
        "|---|---:|---:|---:|---:|---:|---:|---|"
    ]
    for row in categories:
        lines.append(f"| {safe(row['category'])} | {row['total_malicious']} | {row['blocked_malicious']} | "
                     f"{row['allowed_malicious']} | {row['unknown_sent_malicious']} | {row['errors']} | "
                     f"{row['skipped']} | {display(row['detection_rate'])} |")
    lines += ["", "## 7. Missed detections", ""]
    missed = [r for r in rows if r["classification"] == "FN"]
    if not missed:
        lines += ["No evidence-supported FN rows in this input. This is not proof of perfect protection."]
    else:
        lines += ["| Test ID | Parent | Category | Transformation | Evidence |", "|---|---|---|---|---|"]
        for row in missed:
            lines.append("| " + " | ".join(safe(row[k]) for k in
                ("test_id", "parent_test_id", "category", "transformation", "evidence_reference")) + " |")
    lines += ["", "## 8. Baseline vs obfuscated comparison", ""]
    if not pairs["candidate_rows"]:
        lines += ["No variant rows supplied; no baseline/obfuscation conclusion can be drawn."]
    else:
        lines += [f"- {key}: {value}" for key, value in pairs.items()]
        lines += ["", "These are within-run paired dispositions, not proof that every variation preserved attack semantics."]
    lines += ["", "## 9. Limitations", "",
        "Rates are fractions from 0 to 1 and use classified denominators only. Unknowns can bias the observed rates.",
        "Human evidence references must be audited against retained logs. CSV validation cannot establish authenticity.",
        "A WAF allowance is not proof of successful exploitation. Review application/session state and payload validity.",
        "Lab engine versions, thresholds, repetitions, ordering and corpus representativeness limit generalisation.",
        "Unreviewed cases/variants and unsupported XML scenarios provide no detection evidence.",
        "No confidence intervals, population estimates, rule-cause claims or graphs are inferred automatically.",
        "Baseline/variant rows are related observations; do not assume statistical independence.", ""]
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        handle.write("\n".join(lines))

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "reports/initial_analysis.md")
    args = parser.parse_args()
    try:
        generate(args.input, args.output)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"{exc}\n")

if __name__ == "__main__":
    main()
