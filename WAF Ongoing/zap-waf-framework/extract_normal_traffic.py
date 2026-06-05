import json
import re

INPUT = "traffic/normal_traffic_raw.json"
OUTPUT = "traffic/normal_traffic_clean.json"

with open(INPUT, "r", encoding="utf-8") as f:
    data = json.load(f)

messages = data.get("messages", [])
clean = []

def extract_request_line(header):
    first_line = header.splitlines()[0] if header else ""
    parts = first_line.split()
    if len(parts) >= 2:
        method = parts[0]
        url = parts[1]
        return method, url
    return "GET", ""

for msg in messages:
    request_header = msg.get("requestHeader", "")
    request_body = msg.get("requestBody", "")

    method, url = extract_request_line(request_header)

    if "192.168.56.20" not in url:
        continue

    # Ignore broken/empty ZAP placeholder records
    response_header = msg.get("responseHeader", "")
    if response_header.startswith("HTTP/1.0 0"):
        continue

    clean.append({
        "traffic_type": "normal",
        "method": method,
        "url": url,
        "request_body": request_body
    })

with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(clean, f, indent=2)

print(f"Saved {len(clean)} normal requests to {OUTPUT}")
