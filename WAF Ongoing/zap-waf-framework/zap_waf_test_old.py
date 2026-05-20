import requests
import time
import csv
import re
from pathlib import Path
from urllib.parse import quote

ZAP = "http://127.0.0.1:8080"

# Change these per test
MODE = "modsecurity"   # baseline / modsecurity / naxsi

TARGET = "http://192.168.56.20/DVWA/"
# For NAXSI use:
# TARGET = "http://192.168.56.20:8080/DVWA/"

RESULT_DIR = Path("results")
RESULT_DIR.mkdir(exist_ok=True)

OUT_CSV = RESULT_DIR / f"{MODE}_zap_results.csv"


def zap_get(path, params=None):
    url = f"{ZAP}{path}"
    r = requests.get(url, params=params, timeout=30)
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
        status = zap_get("/JSON/spider/view/status/", {
            "scanId": scan_id
        })["status"]

        print(f"    Spider progress: {status}%")

        if int(status) >= 100:
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
        status = zap_get("/JSON/ascan/view/status/", {
            "scanId": scan_id
        })["status"]

        print(f"    Active scan progress: {status}%")

        if int(status) >= 100:
            break

        time.sleep(10)

    print("[+] Active scan completed")


def get_alerts():
    print("[+] Collecting ZAP alerts...")

    data = zap_get("/JSON/core/view/alerts/", {
        "baseurl": TARGET,
        "start": 0,
        "count": 99999
    })

    return data.get("alerts", [])


def get_messages():
    print("[+] Collecting ZAP request/response history...")

    data = zap_get("/JSON/core/view/messages/", {
        "baseurl": TARGET,
        "start": 0,
        "count": 99999
    })

    return data.get("messages", [])


def extract_status_code(message):
    header = message.get("responseHeader", "")
    match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d+)", header)

    if match:
        return int(match.group(1))

    return None


def classify_response(status):
    if status in [403, 406, 501]:
        return "blocked"
    elif status is None:
        return "unknown"
    elif 200 <= status < 400:
        return "allowed"
    elif 400 <= status < 500:
        return "client_error"
    elif 500 <= status < 600:
        return "server_error"
    else:
        return "other"


def summarize(messages, alerts):
    rows = []

    total_requests = len(messages)
    blocked = 0
    allowed = 0
    client_errors = 0
    server_errors = 0
    unknown = 0

    status_counts = {}

    for msg in messages:
        status = extract_status_code(msg)
        category = classify_response(status)

        if status:
            status_counts[status] = status_counts.get(status, 0) + 1

        if category == "blocked":
            blocked += 1
        elif category == "allowed":
            allowed += 1
        elif category == "client_error":
            client_errors += 1
        elif category == "server_error":
            server_errors += 1
        else:
            unknown += 1

    alert_counts = {}

    for alert in alerts:
        name = alert.get("alert", "Unknown")
        alert_counts[name] = alert_counts.get(name, 0) + 1

    block_rate = round((blocked / total_requests) * 100, 2) if total_requests else 0
    allowed_rate = round((allowed / total_requests) * 100, 2) if total_requests else 0

    summary = {
        "mode": MODE,
        "target": TARGET,
        "total_zap_requests": total_requests,
        "allowed_2xx_3xx": allowed,
        "blocked_403_406_501": blocked,
        "client_errors_4xx_other": client_errors,
        "server_errors_5xx": server_errors,
        "unknown": unknown,
        "block_rate_percent": block_rate,
        "allowed_rate_percent": allowed_rate,
        "total_alert_instances": len(alerts),
        "status_code_breakdown": str(status_counts),
        "alert_type_breakdown": str(alert_counts)
    }

    rows.append(summary)
    return rows


def save_csv(rows):
    with open(OUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Saved results to {OUT_CSV}")


def main():
    new_session()
    spider_scan()
    active_scan()

    messages = get_messages()
    alerts = get_alerts()

    rows = summarize(messages, alerts)
    save_csv(rows)

    print("\n===== SUMMARY =====")
    for key, value in rows[0].items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
