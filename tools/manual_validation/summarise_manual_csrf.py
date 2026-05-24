import pandas as pd
from pathlib import Path

files = [
    "manual_tests/results/baseline_manual_csrf.csv",
    "manual_tests/results/modsec_manual_csrf.csv",
    "manual_tests/results/coraza_manual_csrf.csv",
]

existing = [f for f in files if Path(f).exists()]

if not existing:
    raise SystemExit("No manual CSRF result files found.")

df = pd.concat([pd.read_csv(f) for f in existing], ignore_index=True)

summary = df.groupby(
    ["environment", "attack_type", "attack_subtype", "evasion_type"]
).agg(
    sent=("test_id", "count"),
    clean_blocked=("blocked_flag", "sum"),
    allowed=("allowed_flag", "sum"),
    redirected=("redirect_flag", "sum"),
    client_errors=("client_error_flag", "sum"),
    server_errors=("server_error_flag", "sum"),
    timeouts=("timeout_flag", "sum"),
    changed_markers=("contains_changed_message", "sum"),
    mismatch_markers=("contains_mismatch_message", "sum"),
    avg_response_time_ms=("response_time_ms", "mean"),
).reset_index()

summary["clean_block_rate_percent"] = (
    summary["clean_blocked"] / summary["sent"] * 100
).round(2)

summary["allowed_rate_percent"] = (
    summary["allowed"] / summary["sent"] * 100
).round(2)

summary["redirect_rate_percent"] = (
    summary["redirected"] / summary["sent"] * 100
).round(2)

overall = df.groupby("environment").agg(
    sent=("test_id", "count"),
    clean_blocked=("blocked_flag", "sum"),
    allowed=("allowed_flag", "sum"),
    redirected=("redirect_flag", "sum"),
    client_errors=("client_error_flag", "sum"),
    server_errors=("server_error_flag", "sum"),
    timeouts=("timeout_flag", "sum"),
    changed_markers=("contains_changed_message", "sum"),
    mismatch_markers=("contains_mismatch_message", "sum"),
    avg_response_time_ms=("response_time_ms", "mean"),
).reset_index()

overall["clean_block_rate_percent"] = (
    overall["clean_blocked"] / overall["sent"] * 100
).round(2)

overall["allowed_rate_percent"] = (
    overall["allowed"] / overall["sent"] * 100
).round(2)

overall["redirect_rate_percent"] = (
    overall["redirected"] / overall["sent"] * 100
).round(2)

# Non-clean cases for WAFs only
non_clean = df[
    (df["environment"] != "baseline")
    & (df["blocked_flag"] == 0)
].copy()

def classify_non_clean(row):
    if row.get("allowed_flag", 0) == 1:
        return "allowed_logic_request"
    if row.get("redirect_flag", 0) == 1:
        return "redirected_not_clean_block"
    if row.get("server_error_flag", 0) == 1:
        return "server_error_not_clean_block"
    if row.get("client_error_flag", 0) == 1:
        return "client_error_not_clean_block"
    if row.get("timeout_flag", 0) == 1:
        return "timeout"
    return "unknown"

if not non_clean.empty:
    non_clean["non_clean_reason"] = non_clean.apply(classify_non_clean, axis=1)

blocked = df[
    (df["environment"] != "baseline")
    & (df["blocked_flag"] == 1)
].copy()

Path("manual_tests/results").mkdir(parents=True, exist_ok=True)

overall.to_csv("manual_tests/results/manual_csrf_overall_summary.csv", index=False)
summary.to_csv("manual_tests/results/manual_csrf_summary.csv", index=False)
non_clean.to_csv("manual_tests/results/manual_csrf_non_clean_by_waf.csv", index=False)
blocked.to_csv("manual_tests/results/manual_csrf_blocked_by_waf.csv", index=False)

print("\n=== Overall CSRF Manual Summary ===")
print(overall.to_string(index=False))

print("\n=== CSRF Summary by Pattern ===")
print(summary.to_string(index=False))

print("\nFiles written:")
print("manual_tests/results/manual_csrf_overall_summary.csv")
print("manual_tests/results/manual_csrf_summary.csv")
print("manual_tests/results/manual_csrf_non_clean_by_waf.csv")
print("manual_tests/results/manual_csrf_blocked_by_waf.csv")
