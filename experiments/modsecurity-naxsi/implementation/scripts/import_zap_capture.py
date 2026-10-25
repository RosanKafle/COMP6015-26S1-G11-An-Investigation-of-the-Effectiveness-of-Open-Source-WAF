"""Convert a legacy SQLi ZAP capture into review-gated inputs without executing it."""
import argparse
import csv
import json
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from lab_http import validate_url, validate_endpoint
from test_loader import TestCase
from dataclasses import asdict

def convert(source, target, output):
    base = urlsplit(validate_url(target))
    messages = json.loads(source.read_text(encoding="utf-8-sig")).get("messages", [])
    rows = []
    for index, message in enumerate(messages, 1):
        first = message.get("requestHeader", "").splitlines()
        parts = first[0].split() if first else []
        if len(parts) != 3 or parts[0] not in ("GET", "POST"):
            continue
        url = urlsplit(parts[1])
        if url.scheme not in ("http", "https") or (url.scheme, url.netloc) != (base.scheme, base.netloc):
            continue
        path = url.path
        prefix = base.path.rstrip("/")
        if path != prefix + "/vulnerabilities/sqli/":
            continue
        validate_endpoint(path[len(prefix):])
        params = parse_qs(url.query if parts[0] == "GET" else message.get("requestBody", ""),
                          keep_blank_values=True)
        if set(params) - {"id", "Submit"} or len(params.get("id", [])) != 1:
            continue
        rows.append(TestCase(f"CAPTURE_{index:05}", "sqli", "baseline", parts[0],
                             "/vulnerabilities/sqli/", "id", params["id"][0], "MALICIOUS",
                             f"Legacy capture row {index}; label and payload require manual review.",
                             review_status="REQUIRES_REVIEW"))
    if not rows:
        raise ValueError("No compatible SQLi requests found; original capture was not modified.")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(rows[0])))
        writer.writeheader()
        writer.writerows(asdict(r) for r in rows)
    print(f"Imported {len(rows)} review-gated cases; original cookies and outcomes not copied.")

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--source-target", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    try:
        convert(a.input, a.source_target, a.output)
    except (ValueError, OSError) as exc:
        p.exit(2, f"{exc}\n")
if __name__ == "__main__":
    main()
