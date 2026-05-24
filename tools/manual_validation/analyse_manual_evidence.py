import pandas as pd
from pathlib import Path

RESULT_DIR = Path("manual_tests/results")

INPUT_FILES = {
    "sqli": [
        RESULT_DIR / "baseline_manual_sqli.csv",
        RESULT_DIR / "modsec_manual_sqli.csv",
        RESULT_DIR / "coraza_manual_sqli.csv",
    ],
    "csrf": [
        RESULT_DIR / "baseline_manual_csrf.csv",
        RESULT_DIR / "modsec_manual_csrf.csv",
        RESULT_DIR / "coraza_manual_csrf.csv",
    ],
}

BLOCK_CODES = {403, 406, 501}
REDIRECT_CODES = {301, 302, 303, 307, 308}


def load_results():
    frames = []

    for attack_family, files in INPUT_FILES.items():
        for f in files:
            if not f.exists():
                print(f"[WARN] Missing file: {f}")
                continue

            df = pd.read_csv(f)
            df["attack_family"] = attack_family
            df["source_file"] = str(f)

            if "payload_id" in df.columns:
                df["case_id"] = df["payload_id"]
            elif "test_id" in df.columns:
                df["case_id"] = df["test_id"]
            else:
                df["case_id"] = "unknown"

            frames.append(df)

    if not frames:
        raise SystemExit("No manual result files found.")

    return pd.concat(frames, ignore_index=True)


def safe_get(row, col, default=""):
    if col in row and pd.notna(row[col]):
        return row[col]
    return default


def classify_outcome(row):
    status = int(row.get("status_code", 0)) if pd.notna(row.get("status_code", 0)) else 0
    attack_family = row.get("attack_family", "")
    env = row.get("environment", "")

    blocked = int(row.get("blocked_flag", 0)) == 1
    allowed = int(row.get("allowed_flag", 0)) == 1
    redirected = int(row.get("redirect_flag", 0)) == 1
    server_error = int(row.get("server_error_flag", 0)) == 1
    timeout = int(row.get("timeout_flag", 0)) == 1

    if blocked and status in BLOCK_CODES:
        return "clean_waf_block"

    if allowed:
        if env == "baseline":
            return "baseline_allowed_expected"
        if attack_family == "csrf":
            return "logic_gap_allowed"
        return "false_negative_allowed"

    if redirected or status in REDIRECT_CODES:
        return "redirected_not_clean_block"

    if server_error or status >= 500:
        return "server_error_not_clean_block"

    if timeout:
        return "timeout_not_clean_block"

    if 400 <= status <= 499 and status not in BLOCK_CODES:
        return "client_error_not_clean_block"

    return "unknown_outcome"


def classify_correctness(row):
    env = row.get("environment", "")
    attack_family = row.get("attack_family", "")
    outcome = row.get("outcome_class", "")

    # Baseline is no WAF, so allowed vulnerable behaviour is expected evidence.
    if env == "baseline":
        if outcome == "baseline_allowed_expected":
            return "expected_baseline_vulnerable"
        if outcome == "server_error_not_clean_block":
            return "baseline_application_error"
        return "baseline_other"

    # For WAF environments
    if outcome == "clean_waf_block":
        # SQLi clean block is correct. CSRF special-character block is technically a block,
        # but may not mean semantic CSRF detection.
        if attack_family == "csrf":
            return "blocked_but_likely_generic_input_rule"
        return "correct_attack_block"

    if outcome == "false_negative_allowed":
        return "missed_attack_false_negative"

    if outcome == "logic_gap_allowed":
        return "logic_attack_not_detected"

    if outcome == "redirected_not_clean_block":
        return "not_clean_detection_redirect"

    if outcome == "server_error_not_clean_block":
        return "not_clean_detection_server_error"

    return "needs_manual_review"


def explain_reason(row):
    attack_family = row.get("attack_family", "")
    outcome = row.get("outcome_class", "")
    env = row.get("environment", "")
    case_id = row.get("case_id", "")

    attack_subtype = safe_get(row, "attack_subtype")
    evasion_type = safe_get(row, "evasion_type")
    payload = safe_get(row, "payload")
    password_new = safe_get(row, "password_new")

    if env == "baseline":
        if outcome == "baseline_allowed_expected":
            return "No WAF was active. Request reached DVWA and was processed by the application."
        if outcome == "server_error_not_clean_block":
            return "No WAF was active. Payload caused an application/server error rather than a controlled block."
        return "Baseline/no-WAF behaviour; use as comparison point."

    if outcome == "clean_waf_block":
        if attack_family == "sqli":
            return (
                f"Clean WAF block. SQLi pattern '{attack_subtype}/{evasion_type}' "
                f"was likely matched by SQLi/signature or anomaly rules."
            )
        if attack_family == "csrf":
            return (
                f"Clean WAF block. However, CSRF is a workflow attack; this block was likely caused by "
                f"generic input inspection of value '{password_new}', not semantic CSRF detection."
            )
        return "Clean WAF block."

    if outcome == "false_negative_allowed":
        return (
            f"Attack request was allowed through. Pattern '{attack_subtype}/{evasion_type}' "
            f"was not cleanly blocked by the WAF."
        )

    if outcome == "logic_gap_allowed":
        return (
            "CSRF-style workflow request was allowed. This suggests a logic-level gap because the request "
            "resembled normal authenticated application traffic."
        )

    if outcome == "redirected_not_clean_block":
        return (
            "Request was redirected, usually due to session/login/application flow. This is not counted as "
            "a clean WAF detection."
        )

    if outcome == "server_error_not_clean_block":
        return (
            f"Request caused HTTP 500. This is not counted as a clean WAF block because it indicates "
            f"server/application/proxy error behaviour rather than controlled WAF detection."
        )

    if outcome == "client_error_not_clean_block":
        return "Request returned a non-blocking 4xx client error. Requires manual review."

    return "Outcome needs manual review."


def main():
    df = load_results()

    df["outcome_class"] = df.apply(classify_outcome, axis=1)
    df["classification_correctness"] = df.apply(classify_correctness, axis=1)
    df["reason_explanation"] = df.apply(explain_reason, axis=1)

    # Core readable columns
    preferred_cols = [
        "attack_family",
        "environment",
        "case_id",
        "attack_type",
        "attack_subtype",
        "evasion_type",
        "payload",
        "password_new",
        "password_conf",
        "status_code",
        "result",
        "outcome_class",
        "classification_correctness",
        "reason_explanation",
        "response_time_ms",
        "base_url",
        "full_url",
        "source_file",
    ]

    existing_cols = [c for c in preferred_cols if c in df.columns]

    detailed = df[existing_cols].copy()
    detailed.to_csv(RESULT_DIR / "manual_classification_detailed.csv", index=False)

    # What was blocked
    blocked = detailed[detailed["outcome_class"] == "clean_waf_block"].copy()
    blocked.to_csv(RESULT_DIR / "manual_what_was_blocked.csv", index=False)

    # What was not cleanly blocked
    not_clean = detailed[
        (detailed["environment"] != "baseline")
        & (detailed["outcome_class"] != "clean_waf_block")
    ].copy()
    not_clean.to_csv(RESULT_DIR / "manual_what_was_not_cleanly_blocked.csv", index=False)

    # Correct vs incorrect classification summary
    summary = df.groupby(
        ["attack_family", "environment", "outcome_class", "classification_correctness"]
    ).agg(
        count=("case_id", "count"),
        avg_response_time_ms=("response_time_ms", "mean"),
    ).reset_index()

    summary.to_csv(RESULT_DIR / "manual_classification_summary.csv", index=False)

    # Confusion-style counts for manual attack-only evidence
    # Manual files contain attack requests only, not benign traffic.
    confusion_rows = []

    for (attack_family, env), g in df.groupby(["attack_family", "environment"]):
        if env == "baseline":
            continue

        tp = int((g["outcome_class"] == "clean_waf_block").sum())
        fn_allowed = int((g["outcome_class"] == "false_negative_allowed").sum())
        non_clean_redirect = int((g["outcome_class"] == "redirected_not_clean_block").sum())
        non_clean_error = int((g["outcome_class"] == "server_error_not_clean_block").sum())
        total = len(g)

        recall_clean_block = round(tp / total * 100, 2) if total else 0

        confusion_rows.append({
            "attack_family": attack_family,
            "environment": env,
            "attack_requests": total,
            "true_positive_clean_blocks": tp,
            "false_negative_allowed": fn_allowed,
            "redirected_not_clean_block": non_clean_redirect,
            "server_error_not_clean_block": non_clean_error,
            "clean_block_recall_percent": recall_clean_block,
            "note": "Manual attack-only evidence; benign true negatives/false positives require mixed or benign traffic data."
        })

    confusion = pd.DataFrame(confusion_rows)
    confusion.to_csv(RESULT_DIR / "manual_confusion_style_summary.csv", index=False)

    # Markdown summary for report writers
    md = []
    md.append("# Manual Evidence Classification Summary\n")
    md.append("This file explains what was blocked, what was not cleanly blocked, and how each outcome was classified.\n")
    md.append("Clean WAF block is defined as HTTP 403, 406, or 501. Redirects and HTTP 500 server errors are not counted as clean WAF detections.\n")
    md.append("\n## Classification summary\n")
    md.append(summary.to_markdown(index=False))
    md.append("\n\n## Manual confusion-style summary\n")
    md.append(confusion.to_markdown(index=False))
    md.append("\n\n## Key interpretation\n")
    md.append("- SQLi clean blocks indicate the WAF recognised payload/signature-style attack patterns.\n")
    md.append("- SQLi server errors are not counted as clean detections because they indicate application/proxy error behaviour.\n")
    md.append("- CSRF redirects are not clean WAF detections.\n")
    md.append("- CSRF clean block on the special-character password likely reflects generic input filtering, not semantic CSRF detection.\n")
    md.append("- Manual evidence does not include benign traffic, so full false-positive analysis should use mixed/benign automated datasets.\n")

    (RESULT_DIR / "manual_classification_summary.md").write_text("\n".join(md), encoding="utf-8")

    print("\nFiles written:")
    print(RESULT_DIR / "manual_classification_detailed.csv")
    print(RESULT_DIR / "manual_what_was_blocked.csv")
    print(RESULT_DIR / "manual_what_was_not_cleanly_blocked.csv")
    print(RESULT_DIR / "manual_classification_summary.csv")
    print(RESULT_DIR / "manual_confusion_style_summary.csv")
    print(RESULT_DIR / "manual_classification_summary.md")

    print("\n=== Classification summary ===")
    print(summary.to_string(index=False))

    print("\n=== Manual confusion-style summary ===")
    print(confusion.to_string(index=False))


if __name__ == "__main__":
    main()

