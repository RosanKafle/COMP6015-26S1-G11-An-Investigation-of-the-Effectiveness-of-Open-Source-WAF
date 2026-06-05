import json
import csv
import random
import time
import requests
from pathlib import Path

MODE = "naxsi"   # baseline / modsecurity / naxsi

NORMAL_FILE = "traffic/normal_traffic_clean.json"
ATTACK_FILE = "traffic/attack_traffic.json"

RESULT_DIR = Path("results")
RESULT_DIR.mkdir(exist_ok=True)

DETAIL_CSV = RESULT_DIR / f"{MODE}_mixed_traffic_detail.csv"
SUMMARY_CSV = RESULT_DIR / f"{MODE}_mixed_traffic_summary.csv"

PROXIES = {
    "http": "http://192.168.56.20:8080",
    "https": "http://127.0.0.1:8080"
}

USE_ZAP_PROXY = True


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


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


def decision_label(traffic_type, result):
    if traffic_type == "normal":
        if result == "allowed":
            return "true_negative_normal_allowed"
        if result == "blocked":
            return "false_positive_normal_blocked"
        return "normal_other"

    if traffic_type == "malicious":
        if result == "blocked":
            return "true_positive_attack_blocked"
        if result == "allowed":
            return "false_negative_attack_allowed"
        return "attack_other"

    return "unknown"


def send_request(item, session):
    method = item.get("method", "GET").upper()
    url = item.get("url", "")
    body = item.get("request_body", "")

    proxies = PROXIES if USE_ZAP_PROXY else None

    try:
        start = time.time()

        if method == "POST":
            r = session.post(url, data=body, proxies=proxies, timeout=15, allow_redirects=False)
        else:
            r = session.get(url, proxies=proxies, timeout=15, allow_redirects=False)

        elapsed = round(time.time() - start, 4)

        return r.status_code, elapsed, ""

    except Exception as e:
        return None, 0, str(e)


def main():
    normal = load_json(NORMAL_FILE)
    attacks = load_json(ATTACK_FILE)

    # Repeat attacks to make them comparable with normal traffic volume
    expanded_attacks = attacks * 5

    traffic = []

    for item in normal:
        item["actual_attack_type"] = "Normal"
        traffic.append(item)

    for item in expanded_attacks:
        traffic.append(item)

    random.shuffle(traffic)

    session = requests.Session()

    detail_rows = []

    summary = {
        "mode": MODE,
        "total_requests": 0,
        "normal_total": 0,
        "normal_allowed": 0,
        "normal_blocked": 0,
        "malicious_total": 0,
        "malicious_allowed": 0,
        "malicious_blocked": 0,
        "client_errors": 0,
        "server_errors": 0,
        "unknown": 0
    }

    attack_matrix = {}

    for index, item in enumerate(traffic, start=1):
        traffic_type = item.get("traffic_type", "normal")
        actual_attack_type = item.get("actual_attack_type", "Normal")

        status, response_time, error = send_request(item, session)
        result = classify_response(status)
        label = decision_label(traffic_type, result)

        summary["total_requests"] += 1

        if traffic_type == "normal":
            summary["normal_total"] += 1
            if result == "allowed":
                summary["normal_allowed"] += 1
            elif result == "blocked":
                summary["normal_blocked"] += 1

        elif traffic_type == "malicious":
            summary["malicious_total"] += 1
            if result == "allowed":
                summary["malicious_allowed"] += 1
            elif result == "blocked":
                summary["malicious_blocked"] += 1

        if result == "client_error":
            summary["client_errors"] += 1
        elif result == "server_error":
            summary["server_errors"] += 1
        elif result == "unknown":
            summary["unknown"] += 1

        if actual_attack_type not in attack_matrix:
            attack_matrix[actual_attack_type] = {
                "actual_attack_type": actual_attack_type,
                "total": 0,
                "allowed": 0,
                "blocked": 0,
                "client_error": 0,
                "server_error": 0,
                "unknown": 0
            }

        attack_matrix[actual_attack_type]["total"] += 1
        attack_matrix[actual_attack_type][result] = attack_matrix[actual_attack_type].get(result, 0) + 1

        detail_rows.append({
            "mode": MODE,
            "sequence": index,
            "traffic_type": traffic_type,
            "actual_attack_type": actual_attack_type,
            "method": item.get("method", ""),
            "url": item.get("url", ""),
            "status_code": status,
            "result": result,
            "decision_label": label,
            "response_time_seconds": response_time,
            "error": error
        })

        print(f"[{index}/{len(traffic)}] {traffic_type} | {actual_attack_type} | status={status} | {label}")

        time.sleep(0.2)

    total = summary["total_requests"]
    malicious_total = summary["malicious_total"]
    normal_total = summary["normal_total"]

    summary["attack_detection_rate_percent"] = round((summary["malicious_blocked"] / malicious_total) * 100, 2) if malicious_total else 0
    summary["false_negative_rate_percent"] = round((summary["malicious_allowed"] / malicious_total) * 100, 2) if malicious_total else 0
    summary["false_positive_rate_percent"] = round((summary["normal_blocked"] / normal_total) * 100, 2) if normal_total else 0
    summary["normal_allow_rate_percent"] = round((summary["normal_allowed"] / normal_total) * 100, 2) if normal_total else 0

    with open(DETAIL_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=detail_rows[0].keys())
        writer.writeheader()
        writer.writerows(detail_rows)

    with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=summary.keys())
        writer.writeheader()
        writer.writerow(summary)

    matrix_csv = RESULT_DIR / f"{MODE}_mixed_attack_matrix.csv"
    matrix_rows = list(attack_matrix.values())

    with open(matrix_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=matrix_rows[0].keys())
        writer.writeheader()
        writer.writerows(matrix_rows)

    print("\n===== MIXED TRAFFIC SUMMARY =====")
    for k, v in summary.items():
        print(f"{k}: {v}")

    print(f"\n[+] Saved detail: {DETAIL_CSV}")
    print(f"[+] Saved summary: {SUMMARY_CSV}")
    print(f"[+] Saved matrix: {matrix_csv}")


if __name__ == "__main__":
    main()
