"""Check HTTP reachability only; no exploit requests."""
import argparse
import csv
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from lab_http import NETWORK_ERRORS, request, validate_url

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ["component", "url", "reachable", "http_status", "timestamp", "notes"]

def check(config: Path, output: Path) -> list[dict]:
    settings = json.loads(config.read_text(encoding="utf-8-sig"))
    timeout = float(settings.get("timeout", 5))
    if not 0 < timeout <= 120:
        raise ValueError("timeout must be greater than 0 and at most 120 seconds.")
    components = settings.get("components")
    if not isinstance(components, dict) or not components:
        raise ValueError("environment config requires a nonempty components object.")
    selected = {}
    for name, value in components.items():
        key = {"dvwa": "TARGET_URL", "modsecurity": "MODSECURITY_URL",
               "naxsi": "NAXSI_URL", "zap": "ZAP_URL", "zap": "ZAP_URL"}.get(name, name.upper() + "_URL")
        selected[name] = validate_url(os.environ.get(key, value))
    rows = []
    for name, url in selected.items():
        row = dict(component=name, url=url, reachable=False, http_status="",
                   timestamp=datetime.now(timezone.utc).isoformat(), notes="")
        try:
            response = request(url, endpoint="/JSON/core/view/version/" if name == "zap" else "/", headers={"X-ZAP-API-Key": os.environ.get("ZAP_API_KEY", "")} if name == "zap" else None, timeout=timeout, max_bytes=1024)
            row.update(reachable=True, http_status=response.status,
                       notes="HTTP responded; identity, authentication and WAF mode NOT VERIFIED.")
        except NETWORK_ERRORS as exc:
            row["notes"] = f"Connection failed ({type(exc).__name__}); check lab host, port and TLS."
        rows.append(row)
        logging.info("%s reachable=%s status=%s %s", name, row["reachable"], row["http_status"], row["notes"])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return rows

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "config/environment.example.json")
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/environment_check.csv")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        rows = check(args.config, args.output)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"Environment check failed: {exc}\n")
    if not all(r["reachable"] for r in rows):
        parser.exit(1, "Some components did not respond; see the CSV.\n")

if __name__ == "__main__":
    main()
