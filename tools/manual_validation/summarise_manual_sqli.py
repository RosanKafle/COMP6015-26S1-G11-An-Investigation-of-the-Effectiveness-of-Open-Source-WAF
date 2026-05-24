import pandas as pd
from pathlib import Path

files = [
    "manual_tests/results/baseline_manual_sqli.csv",
    "manual_tests/results/modsec_manual_sqli.csv",
    "manual_tests/results/coraza_manual_sqli.csv",
]

existing = [f for f in files if Path(f).exists()]

if not existing:
    raise SystemExit("No manual SQLi result files found.")

df = pd.concat([pd.read_csv(f) for f in existing], ignore_index=True)

summary = df.groupby(
    ["environment", "attack_type", "attack_subtype", "evasion_type"]
).agg(
    sent=("payload_id", "count"),
    clean_blocked=("blocked_flag", "sum"),
    allowed=("allowed_flag", "sum"),
    redirected=("redirect_flag", "sum"),
    client_errors=("client_error_flag", "sum"),
    server_errors=("server_error_flag", "sum"),
    timeouts=("timeout_flag", "sum"),
    avg_response_time_ms=("response_time_ms", "mean"),
    sql_error_markers=("contains_sql_error", "sum"),
    dvwa_result_markers=("contains_dvwa_result", "sum"),
).reset_index()

summary["detection_rate_percent"] = (
    summary["clean_blocked"] / summary["sent"] * 100
).round(2)

summary["allowed_rate_percent"] = (
    summary["allowed"] / summary["sent"] * 100
).round(2)

summary["server_error_rate_percent"] = (
    summary["server_errors"] / summary["sent"] * 100
).round(2)

# WAF missed = attack not cleanly blocked, excluding baseline
missed = df[
    (df["environment"] != "baseline")
    & (df["blocked_flag"] == 0)
].copy()

def classify_reason(row):
    if row.get("allowed_flag", 0) == 1:
        return "allowed_payload"
    if row.get("redirect_flag", 0) == 1:
        return "redirected_session"
    if row.get("server_error_flag", 0) == 1:
        return "server_error_not_clean_block"
    if row.get("timeout_flag", 0) == 1:
        return "timeout"
    if row.get("client_error_flag", 0) == 1:
        return "client_error"
    return "unknown"

if not missed.empty:
    missed["miss_reason"] = missed.apply(classify_reason, axis=1)

blocked = df[
    (df["environment"] != "baseline")
    & (df["blocked_flag"] == 1)
].copy()

Path("manual_tests/results").mkdir(parents=True, exist_ok=True)

summary.to_csv("manual_tests/results/manual_sqli_summary.csv", index=False)
missed.to_csv("manual_tests/results/manual_sqli_missed_by_waf.csv", index=False)
blocked.to_csv("manual_tests/results/manual_sqli_blocked_by_waf.csv", index=False)

# Overall compact table
overall = df.groupby("environment").agg(
    sent=("payload_id", "count"),
    clean_blocked=("blocked_flag", "sum"),
    allowed=("allowed_flag", "sum"),
    redirected=("redirect_flag", "sum"),
    client_errors=("client_error_flag", "sum"),
    server_errors=("server_error_flag", "sum"),
    timeouts=("timeout_flag", "sum"),
    avg_response_time_ms=("response_time_ms", "mean"),
).reset_index()

overall["detection_rate_percent"] = (
    overall["clean_blocked"] / overall["sent"] * 100
).round(2)

overall["allowed_rate_percent"] = (
    overall["allowed"] / overall["sent"] * 100
).round(2)

overall["server_error_rate_percent"] = (
    overall["server_errors"] / overall["sent"] * 100
).round(2)

overall.to_csv("manual_tests/results/manual_sqli_overall_summary.csv", index=False)

print("\n=== Overall SQLi Manual Summary ===")
print(overall.to_string(index=False))

print("\n=== SQLi Summary by Pattern ===")
print(summary.to_string(index=False))

print("\nFiles written:")
print("manual_tests/results/manual_sqli_overall_summary.csv")
print("manual_tests/results/manual_sqli_summary.csv")
print("manual_tests/results/manual_sqli_missed_by_waf.csv")
print("manual_tests/results/manual_sqli_blocked_by_waf.csv")
