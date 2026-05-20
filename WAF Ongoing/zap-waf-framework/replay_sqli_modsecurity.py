import csv
import json
import requests
import time

INPUT_FILE = "traffic/sqli_raw.json"
OUTPUT_FILE = "results/modsecurity_sqli_results.csv"

PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

session = requests.Session()

with open(INPUT_FILE, "r") as f:
    data = json.load(f)

messages = data.get("messages", [])

results = []

print(f"[+] Replaying {len(messages)} SQLi requests")

for i, msg in enumerate(messages):

    try:

        request_header = msg.get("requestHeader", "")
        first_line = request_header.splitlines()[0]

        parts = first_line.split()

        if len(parts) < 2:
            continue

        method = parts[0]
        url = parts[1]

        start = time.time()

        r = session.request(
            method,
            url,
            proxies=PROXIES,
            timeout=15,
            allow_redirects=False
        )

        elapsed = round(time.time() - start, 4)

        status = r.status_code

        if status in [403, 406]:
            outcome = "blocked"

        elif status >= 500:
            outcome = "server_error"

        elif status >= 400:
            outcome = "client_error"

        else:
            outcome = "allowed"

        print(f"[{i+1}] {status} -> {outcome}")

        results.append([
            i + 1,
            method,
            url,
            status,
            outcome,
            elapsed
        ])

    except Exception as e:

        print(f"[{i+1}] ERROR: {e}")

        results.append([
            i + 1,
            "ERROR",
            "ERROR",
            "ERROR",
            str(e),
            0
        ])

with open(OUTPUT_FILE, "w", newline="") as f:

    writer = csv.writer(f)

    writer.writerow([
        "request_id",
        "method",
        "url",
        "status_code",
        "outcome",
        "response_time"
    ])

    writer.writerows(results)

print(f"[+] Results saved to {OUTPUT_FILE}")
