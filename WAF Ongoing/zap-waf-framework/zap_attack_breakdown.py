import requests
import time
import csv
import re
from pathlib import Path

ZAP = "http://127.0.0.1:8080"

# Change this for each test
MODE = "naxsi"   # baseline / modsecurity / naxsi

TARGET = "http://192.168.56.20:8080/DVWA/"
# For NAXSI:
# TARGET = "http://192.168.56.20:8080/DVWA/"

RESULT_DIR = Path("results")
RESULT_DIR.mkdir(exist_ok=True)

SUMMARY_CSV = RESULT_DIR / f"{MODE}_summary.csv"
BREAKDOWN_CSV = RESULT_DIR / f"{MODE}_attack_breakdown.csv"
MESSAGES_CSV = RESULT_DIR / f"{MODE}_all_zap_messages.csv"
ALERTS_CSV = RESULT_DIR / f"{MODE}_zap_alerts.csv"


def zap_get(path, params=None):
    r = requests.get(f"{ZAP}{path}", params=params, timeout=60)
    r.raise_for_status()
    return r.json()


def new_session():
    print("[+] Creating fresh ZAP session...")
    zap_get("/JSON/core/action/newSession/", {
        "name": f"{MODE}_session",
        "overwrite": "true"
    })


def spider_scan():
    print(f"[+] Starting spider scan on {TARGET}")
    data = zap_get("/JSON/spider/action/scan/", {
        "url": TARGET,
        "recurse": "true"
    })

    scan_id = data["scan"]

    while True:
        status = int(zap_get("/JSON/spider/view/status/", {
            "scanId": scan_id
        })["status"])

        print(f"    Spider progress: {status}%")

        if status >= 100:
            break

        time.sleep(5)

    print("[+] Spider completed")


def active_scan():
    print(f"[+] Starting active scan on {TARGET}")
    data = zap_get("/JSON/ascan/action/scan/", {
        "url": TARGET,
        "recurse": "true",
        "inScopeOnly": "false"
    })

    scan_id = data["scan"]

    while True:
        status = int(zap_get("/JSON/ascan/view/status/", {
            "scanId": scan_id
        })["status"])

        print(f"    Active scan progress: {status}%")

        if status >= 100:
            break

        time.sleep(10)

    print("[+] Active scan completed")


def get_messages():
    print("[+] Collecting ZAP request/response history...")
    data = zap_get("/JSON/core/view/messages/", {
        "baseurl": TARGET,
        "start": 0,
        "count": 999999
    })
    return data.get("messages", [])


def get_alerts():
    print("[+] Collecting ZAP alerts...")
    data = zap_get("/JSON/core/view/alerts/", {
        "baseurl": TARGET,
        "start": 0,
        "count": 999999
    })
    return data.get("alerts", [])


def extract_status_code(message):
    header = message.get("responseHeader", "")
    match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d+)", header)
    if match:
        return int(match.group(1))
    return None


def classify_response(status):
    if status in [403, 406, 501]:
        return "blocked"
    if status is None:
        return "unknown"
    if 200 <= status < 400:
        return "allowed"
    if 400 <= status < 500:
        return "client_error"
    if 500 <= status < 600:
        return "server_error"
    return "other"


def get_request_text(message):
    return (
        message.get("requestHeader", "") + "\n" +
        message.get("requestBody", "") + "\n" +
        message.get("url", "")
    ).lower()


def classify_attack(message):
    text = get_request_text(message)

    # DVWA endpoint-based classification
    if "/vulnerabilities/sqli" in text or "union" in text or "select" in text or "%27" in text or "' or" in text:
        return "SQL Injection"

    if "/vulnerabilities/xss" in text or "<script" in text or "%3cscript" in text or "alert(" in text:
        return "Cross-Site Scripting"

    if "/vulnerabilities/fi" in text or "/etc/passwd" in text or "%2fetc%2fpasswd" in text or "../" in text or "%2e%2e" in text:
        return "Path Traversal / File Inclusion"

    if "/vulnerabilities/exec" in text or ";whoami" in text or "127.0.0.1" in text or "cmd=" in text:
        return "Command Injection"

    if "/vulnerabilities/upload" in text or "multipart/form-data" in text or "filename=" in text:
        return "File Upload"

    if "/vulnerabilities/csrf" in text:
        return "CSRF"

    if "/vulnerabilities/brute" in text or "username=" in text or "password=" in text:
        return "Brute Force / Authentication"

    if "/vulnerabilities/open_redirect" in text or "redirect" in text:
        return "Open Redirect"

    if "/.git" in text or "directory" in text:
        return "Forced Browsing / Directory Discovery"

    if "user-agent" in text:
        return "Header / User-Agent Fuzzing"

    return "Other / General Probe"


def analyze_messages(messages):
    attack_stats = {}

    detailed_rows = []

    for msg in messages:
        url = msg.get("url", "")
        method = msg.get("method", "")
        status = extract_status_code(msg)
        result = classify_response(status)
        attack_type = classify_attack(msg)

        if attack_type not in attack_stats:
            attack_stats[attack_type] = {
                "mode": MODE,
                "attack_type": attack_type,
                "total_requests": 0,
                "allowed": 0,
                "blocked": 0,
                "client_errors": 0,
                "server_errors": 0,
                "unknown": 0
            }

        attack_stats[attack_type]["total_requests"] += 1

        if result == "allowed":
            attack_stats[attack_type]["allowed"] += 1
        elif result == "blocked":
            attack_stats[attack_type]["blocked"] += 1
        elif result == "client_error":
            attack_stats[attack_type]["client_errors"] += 1
        elif result == "server_error":
            attack_stats[attack_type]["server_errors"] += 1
        else:
            attack_stats[attack_type]["unknown"] += 1

        detailed_rows.append({
            "mode": MODE,
            "attack_type": attack_type,
            "method": method,
            "url": url,
            "status_code": status,
            "result": result
        })

    breakdown_rows = []

    for attack_type, stats in attack_stats.items():
        total = stats["total_requests"]
        blocked = stats["blocked"]
        allowed = stats["allowed"]

        stats["block_rate_percent"] = round((blocked / total) * 100, 2) if total else 0
        stats["allowed_rate_percent"] = round((allowed / total) * 100, 2) if total else 0

        breakdown_rows.append(stats)

    breakdown_rows.sort(key=lambda x: x["total_requests"], reverse=True)

    return breakdown_rows, detailed_rows


def analyze_alerts(alerts):
    alert_rows = []

    for alert in alerts:
        alert_rows.append({
            "mode": MODE,
            "alert": alert.get("alert", ""),
            "risk": alert.get("risk", ""),
            "confidence": alert.get("confidence", ""),
            "url": alert.get("url", ""),
            "param": alert.get("param", ""),
            "attack": alert.get("attack", ""),
            "evidence": alert.get("evidence", ""),
            "cweid": alert.get("cweid", ""),
            "wascid": alert.get("wascid", "")
        })

    return alert_rows


def save_csv(path, rows):
    if not rows:
        print(f"[!] No rows to save for {path}")
        return

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Saved {path}")


def build_summary(messages, alerts, breakdown_rows):
    total_requests = len(messages)
    total_blocked = sum(row["blocked"] for row in breakdown_rows)
    total_allowed = sum(row["allowed"] for row in breakdown_rows)
    total_client_errors = sum(row["client_errors"] for row in breakdown_rows)
    total_server_errors = sum(row["server_errors"] for row in breakdown_rows)

    summary = [{
        "mode": MODE,
        "target": TARGET,
        "total_zap_requests": total_requests,
        "total_allowed": total_allowed,
        "total_blocked": total_blocked,
        "total_client_errors": total_client_errors,
        "total_server_errors": total_server_errors,
        "total_alerts": len(alerts),
        "overall_block_rate_percent": round((total_blocked / total_requests) * 100, 2) if total_requests else 0,
        "overall_allowed_rate_percent": round((total_allowed / total_requests) * 100, 2) if total_requests else 0
    }]

    return summary


def main():
    new_session()
    spider_scan()
    active_scan()

    messages = get_messages()
    alerts = get_alerts()

    breakdown_rows, detailed_rows = analyze_messages(messages)
    alert_rows = analyze_alerts(alerts)
    summary_rows = build_summary(messages, alerts, breakdown_rows)

    save_csv(SUMMARY_CSV, summary_rows)
    save_csv(BREAKDOWN_CSV, breakdown_rows)
    save_csv(MESSAGES_CSV, detailed_rows)
    save_csv(ALERTS_CSV, alert_rows)

    print("\n===== OVERALL SUMMARY =====")
    for k, v in summary_rows[0].items():
        print(f"{k}: {v}")

    print("\n===== ATTACK BREAKDOWN =====")
    for row in breakdown_rows:
        print(
            f"{row['attack_type']}: "
            f"total={row['total_requests']}, "
            f"blocked={row['blocked']}, "
            f"allowed={row['allowed']}, "
            f"block_rate={row['block_rate_percent']}%"
        )


if __name__ == "__main__":
    main()
