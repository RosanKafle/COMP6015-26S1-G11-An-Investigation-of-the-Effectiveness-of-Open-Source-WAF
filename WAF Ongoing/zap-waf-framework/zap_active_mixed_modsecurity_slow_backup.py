import csv
import random
import time
import subprocess
from pathlib import Path
from urllib.parse import urlencode
import requests

TARGET = "http://192.168.56.20/DVWA"
ZAP_PROXY = "http://127.0.0.1:8080"
ZAP_API = "http://127.0.0.1:8080"

UBUNTU_USER = "bishal"
UBUNTU_IP = "192.168.56.20"
MODSEC_LOG = "/var/log/apache2/modsec_audit.log"

RESULTS = Path("results")
RESULTS.mkdir(exist_ok=True)

DETAIL_CSV = RESULTS / "modsecurity_mixed_detail.csv"
SUMMARY_CSV = RESULTS / "modsecurity_mixed_summary.csv"
MATRIX_CSV = RESULTS / "modsecurity_classification_matrix.csv"

PROXIES = {
    "http": ZAP_PROXY,
    "https": ZAP_PROXY,
}

CRS_MAP = {
    "941": "XSS",
    "942": "SQL Injection",
    "930": "Path Traversal",
    "932": "Command Injection",
}

NORMAL_REQUESTS = [
    "/",
    "/login.php",
    "/security.php",
    "/instructions.php",
    "/vulnerabilities/sqli/",
    "/vulnerabilities/xss_r/",
    "/vulnerabilities/exec/",
    "/vulnerabilities/fi/",
]

ATTACKS = {
    "SQL Injection": {
        "endpoint": "/vulnerabilities/sqli/",
        "param": "id",
        "extra": {"Submit": "Submit"},
        "expected_rule": "942",
        "payloads": [
            "1' OR '1'='1",
            "1 UNION SELECT user,password FROM users",
            "' OR 1=1#",
            "admin' --",
            "1' AND SLEEP(5)#",
        ],
    },
    "XSS": {
        "endpoint": "/vulnerabilities/xss_r/",
        "param": "name",
        "extra": {},
        "expected_rule": "941",
        "payloads": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
        ],
    },
    "Path Traversal": {
        "endpoint": "/vulnerabilities/fi/",
        "param": "page",
        "extra": {},
        "expected_rule": "930",
        "payloads": [
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "/etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
        ],
    },
    "Command Injection": {
        "endpoint": "/vulnerabilities/exec/",
        "param": "ip",
        "extra": {"Submit": "Submit"},
        "expected_rule": "932",
        "payloads": [
            "127.0.0.1; whoami",
            "127.0.0.1 && id",
            "127.0.0.1 | whoami",
            "127.0.0.1; cat /etc/passwd",
        ],
    },
}


def shell(cmd):
    return subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=10)


def remote_count(pattern):
    cmd = f"ssh -o ConnectTimeout=5 {UBUNTU_USER}@{UBUNTU_IP} \"grep -c '{pattern}' {MODSEC_LOG}\""
    try:
        r = shell(cmd)
        if r.returncode == 0:
            return int(r.stdout.strip() or 0)
    except Exception:
        pass
    return 0


def check_zap():
    try:
        r = requests.get(f"{ZAP_API}/JSON/core/view/version/", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def classify_status(status):
    if status in [403, 406]:
        return "blocked"
    if status in [200, 201, 202]:
        return "allowed"
    if status in [301, 302]:
        return "redirect"
    if status and 400 <= status < 500:
        return "client_error"
    if status and status >= 500:
        return "server_error"
    return "unknown"


def build_normal_request():
    endpoint = random.choice(NORMAL_REQUESTS)
    return {
        "actual_type": "Normal",
        "expected_rule": "none",
        "url": TARGET + endpoint,
        "payload": "",
    }


def build_attack_request(attack_type, config):
    payload = random.choice(config["payloads"])
    params = {config["param"]: payload}
    params.update(config["extra"])
    url = TARGET + config["endpoint"] + "?" + urlencode(params)

    return {
        "actual_type": attack_type,
        "expected_rule": config["expected_rule"],
        "url": url,
        "payload": payload,
    }


def infer_detected_type(before_counts, after_counts):
    deltas = {}

    for rule in CRS_MAP:
        deltas[rule] = after_counts[rule] - before_counts[rule]

    detected_rules = [rule for rule, count in deltas.items() if count > 0]

    if not detected_rules:
        return "Not Detected", "none"

    strongest = max(detected_rules, key=lambda r: deltas[r])
    return CRS_MAP[strongest], strongest


def main():
    if not check_zap():
        print("[-] ZAP API is not running.")
        return

    print("[+] Building mixed traffic dataset...")

    traffic = []

    for _ in range(120):
        traffic.append(build_normal_request())

    for attack_type, config in ATTACKS.items():
        for _ in range(120):
            traffic.append(build_attack_request(attack_type, config))

    random.shuffle(traffic)

    rows = []
    matrix = {}

    counts = {
        "total": 0,
        "normal_total": 0,
        "normal_allowed": 0,
        "normal_blocked": 0,
        "malicious_total": 0,
        "malicious_allowed": 0,
        "malicious_blocked": 0,
        "misclassified": 0,
        "not_detected_attacks": 0,
    }

    session = requests.Session()

    for i, item in enumerate(traffic, start=1):
        before = {rule: remote_count(rule) for rule in CRS_MAP}

        start = time.time()

        try:
            r = session.get(
                item["url"],
                proxies=PROXIES,
                timeout=15,
                allow_redirects=False,
            )
            status = r.status_code
            error = ""
        except Exception as e:
            status = None
            error = str(e)

        elapsed = round(time.time() - start, 4)

        after = {rule: remote_count(rule) for rule in CRS_MAP}

        outcome = classify_status(status)
        detected_type, detected_rule = infer_detected_type(before, after)

        actual = item["actual_type"]

        counts["total"] += 1

        if actual == "Normal":
            counts["normal_total"] += 1
            if outcome == "blocked":
                counts["normal_blocked"] += 1
            else:
                counts["normal_allowed"] += 1
        else:
            counts["malicious_total"] += 1
            if outcome == "blocked":
                counts["malicious_blocked"] += 1
            elif outcome == "allowed":
                counts["malicious_allowed"] += 1

            if detected_type == "Not Detected":
                counts["not_detected_attacks"] += 1
            elif detected_type != actual:
                counts["misclassified"] += 1

        matrix.setdefault(actual, {})
        matrix[actual].setdefault(detected_type, 0)
        matrix[actual][detected_type] += 1

        rows.append({
            "request_id": i,
            "actual_type": actual,
            "detected_type": detected_type,
            "detected_rule_group": detected_rule,
            "status_code": status,
            "outcome": outcome,
            "payload": item["payload"],
            "url": item["url"],
            "response_time": elapsed,
            "error": error,
        })

        print(f"[{i}/{len(traffic)}] actual={actual} detected={detected_type} status={status} outcome={outcome}")

        time.sleep(0.02)

    total = counts["total"]
    normal_total = counts["normal_total"]
    malicious_total = counts["malicious_total"]

    summary = {
        "mode": "modsecurity_mixed",
        "total_requests": total,
        "normal_total": normal_total,
        "normal_allowed": counts["normal_allowed"],
        "normal_blocked_false_positive": counts["normal_blocked"],
        "malicious_total": malicious_total,
        "malicious_blocked": counts["malicious_blocked"],
        "malicious_allowed_false_negative": counts["malicious_allowed"],
        "not_detected_attacks": counts["not_detected_attacks"],
        "misclassified_attacks": counts["misclassified"],
        "false_positive_rate_percent": round((counts["normal_blocked"] / normal_total) * 100, 2) if normal_total else 0,
        "false_negative_rate_percent": round((counts["malicious_allowed"] / malicious_total) * 100, 2) if malicious_total else 0,
        "attack_block_rate_percent": round((counts["malicious_blocked"] / malicious_total) * 100, 2) if malicious_total else 0,
    }

    with open(DETAIL_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=summary.keys())
        writer.writeheader()
        writer.writerow(summary)

    all_detected = sorted({det for actual in matrix for det in matrix[actual]})
    all_actual = sorted(matrix.keys())

    with open(MATRIX_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["actual_attack_type"] + all_detected)

        for actual in all_actual:
            writer.writerow([actual] + [matrix[actual].get(det, 0) for det in all_detected])

    print("\n===== MIXED TRAFFIC SUMMARY =====")
    for k, v in summary.items():
        print(f"{k}: {v}")

    print(f"\n[+] Detail saved: {DETAIL_CSV}")
    print(f"[+] Summary saved: {SUMMARY_CSV}")
    print(f"[+] Matrix saved: {MATRIX_CSV}")


if __name__ == "__main__":
    main()
