import csv
import time
import subprocess
from pathlib import Path

import requests

TARGET = "http://192.168.56.20/DVWA/"
ZAP = "http://127.0.0.1:8080"

UBUNTU_USER = "bishal"
UBUNTU_IP = "192.168.56.20"
MODSEC_LOG = "/var/log/apache2/modsec_audit.log"

RESULTS = Path("results")
RESULTS.mkdir(exist_ok=True)

SUMMARY_CSV = RESULTS / "zap_active_modsecurity_summary.csv"
ALERTS_CSV = RESULTS / "zap_active_modsecurity_alerts.csv"
MESSAGES_CSV = RESULTS / "zap_active_modsecurity_messages.csv"

TESTS = {
    "SQL Injection": {
        "zap_keywords": ["SQL Injection"],
        "crs_rule_group": "942",
    },
    "XSS": {
        "zap_keywords": ["Cross Site Scripting", "XSS"],
        "crs_rule_group": "941",
    },
    "Path Traversal": {
        "zap_keywords": ["Path Traversal", "Remote File Inclusion", "Local File Inclusion"],
        "crs_rule_group": "930",
    },
    "Command Injection": {
        "zap_keywords": ["Remote OS Command Injection", "Command Injection"],
        "crs_rule_group": "932",
    },
}


def zap_get(path, params=None):
    r = requests.get(f"{ZAP}{path}", params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def remote_count(pattern):
    cmd = (
        f"ssh -o ConnectTimeout=5 {UBUNTU_USER}@{UBUNTU_IP} "
        f"\"grep -c '{pattern}' {MODSEC_LOG}\""
    )
    try:
        r = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=10)
        if r.returncode == 0:
            return int(r.stdout.strip() or 0)
    except Exception:
        pass
    return 0


def new_session(name):
    zap_get("/JSON/core/action/newSession/", {
        "name": name,
        "overwrite": "true"
    })


def spider():
    print("[+] Starting spider...")
    result = zap_get("/JSON/spider/action/scan/", {
        "url": TARGET,
        "maxChildren": "0",
        "recurse": "true"
    })
    scan_id = result["scan"]

    while True:
        status = zap_get("/JSON/spider/view/status/", {"scanId": scan_id})["status"]
        print(f"    Spider progress: {status}%")
        if int(status) >= 100:
            break
        time.sleep(3)


def disable_all_scanners():
    zap_get("/JSON/ascan/action/disableAllScanners/")


def enable_scanners_by_keywords(keywords):
    scanners = zap_get("/JSON/ascan/view/scanners/")["scanners"]
    enabled = []

    for scanner in scanners:
        name = scanner.get("name", "")
        scanner_id = scanner.get("id", "")

        if any(k.lower() in name.lower() for k in keywords):
            zap_get("/JSON/ascan/action/enableScanners/", {"ids": scanner_id})
            enabled.append(name)

    return enabled


def run_active_scan():
    print("[+] Starting ZAP active scan...")
    result = zap_get("/JSON/ascan/action/scan/", {
        "url": TARGET,
        "recurse": "true",
        "inScopeOnly": "false"
    })
    scan_id = result["scan"]

    while True:
        status = zap_get("/JSON/ascan/view/status/", {"scanId": scan_id})["status"]
        print(f"    Active scan progress: {status}%")
        if int(status) >= 100:
            break
        time.sleep(5)


def collect_messages():
    data = zap_get("/JSON/core/view/messages/", {
        "baseurl": "http://192.168.56.20",
        "start": "0",
        "count": "99999"
    })
    return data.get("messages", [])


def collect_alerts():
    data = zap_get("/JSON/core/view/alerts/", {
        "baseurl": "http://192.168.56.20",
        "start": "0",
        "count": "99999"
    })
    return data.get("alerts", [])


def classify_status(code):
    try:
        code = int(code)
    except Exception:
        return "unknown"

    if code in [403, 406]:
        return "blocked"
    if code in [200, 201, 202]:
        return "allowed"
    if code in [301, 302]:
        return "redirect"
    if 400 <= code < 500:
        return "client_error"
    if code >= 500:
        return "server_error"
    return "unknown"


def analyse_messages(messages):
    counts = {
        "total_messages": 0,
        "blocked": 0,
        "allowed": 0,
        "redirect": 0,
        "client_error": 0,
        "server_error": 0,
        "unknown": 0,
    }

    rows = []

    for m in messages:
        url = m.get("requestHeader", "")
        response = m.get("responseHeader", "")

        if "192.168.56.20" not in url:
            continue

        status = "unknown"
        if response.startswith("HTTP/"):
            parts = response.split()
            if len(parts) >= 2:
                status = parts[1]

        outcome = classify_status(status)

        counts["total_messages"] += 1
        counts[outcome] += 1

        rows.append({
            "url": url.splitlines()[0] if url else "",
            "status_code": status,
            "outcome": outcome,
        })

    return counts, rows


def main():
    all_summary = []
    all_alerts = []
    all_messages = []

    print("[+] Checking ZAP...")
    version = zap_get("/JSON/core/view/version/")
    print(version)

    for attack_type, config in TESTS.items():
        print(f"\n===== ZAP ACTIVE TEST: {attack_type} =====")

        before_rule_hits = remote_count(config["crs_rule_group"])
        before_denied = remote_count("Access denied")

        new_session(f"zap_active_{attack_type.replace(' ', '_')}")
        spider()

        disable_all_scanners()
        enabled = enable_scanners_by_keywords(config["zap_keywords"])

        print("[+] Enabled scanners:")
        for e in enabled:
            print("   -", e)

        if not enabled:
            print(f"[!] No ZAP scanners found for {attack_type}. Skipping.")
            continue

        run_active_scan()

        messages = collect_messages()
        alerts = collect_alerts()

        counts, message_rows = analyse_messages(messages)

        after_rule_hits = remote_count(config["crs_rule_group"])
        after_denied = remote_count("Access denied")

        rule_hits = after_rule_hits - before_rule_hits
        denied_events = after_denied - before_denied

        total = counts["total_messages"]
        detection_rate = round((counts["blocked"] / total) * 100, 2) if total else 0
        allowed_rate = round((counts["allowed"] / total) * 100, 2) if total else 0

        summary = {
            "attack_type": attack_type,
            "zap_enabled_scanners": "; ".join(enabled),
            "total_zap_messages": total,
            "blocked_403_406": counts["blocked"],
            "allowed_200": counts["allowed"],
            "redirect_301_302": counts["redirect"],
            "client_errors": counts["client_error"],
            "server_errors": counts["server_error"],
            "unknown": counts["unknown"],
            "crs_rule_group": config["crs_rule_group"],
            "crs_rule_hits": rule_hits,
            "access_denied_events": denied_events,
            "block_rate_percent": detection_rate,
            "allow_rate_percent": allowed_rate,
        }

        all_summary.append(summary)

        for a in alerts:
            all_alerts.append({
                "attack_type": attack_type,
                "alert": a.get("alert", ""),
                "risk": a.get("risk", ""),
                "confidence": a.get("confidence", ""),
                "url": a.get("url", ""),
                "param": a.get("param", ""),
            })

        for r in message_rows:
            r["attack_type"] = attack_type
            all_messages.append(r)

        print("===== SUMMARY =====")
        for k, v in summary.items():
            print(f"{k}: {v}")

    if all_summary:
        with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=all_summary[0].keys())
            writer.writeheader()
            writer.writerows(all_summary)

    if all_alerts:
        with open(ALERTS_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=all_alerts[0].keys())
            writer.writeheader()
            writer.writerows(all_alerts)

    if all_messages:
        with open(MESSAGES_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=all_messages[0].keys())
            writer.writeheader()
            writer.writerows(all_messages)

    print("\n[+] Saved:")
    print(SUMMARY_CSV)
    print(ALERTS_CSV)
    print(MESSAGES_CSV)


if __name__ == "__main__":
    main()
