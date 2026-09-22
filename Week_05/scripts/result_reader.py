"""Validate collected/enriched CSVs before comparison or analysis."""
import csv
from datetime import datetime
from pathlib import Path
from classification import classify
from result_writer import FIELDS

NO_RESULTS = "No real experiment result file was supplied. Analysis cannot be generated."

def read_results(path: Path | None) -> list[dict]:
    if path is None or not path.is_file():
        raise ValueError(NO_RESULTS)
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or set(FIELDS) - set(reader.fieldnames):
            raise ValueError("Result CSV lacks the collection schema; legacy/template files cannot be analysed directly.")
        rows = list(reader)
    if not rows:
        raise ValueError(NO_RESULTS)
    seen = set()
    for row in rows:
        if None in row or any(v is None for v in row.values()):
            raise ValueError("Malformed result CSV row.")
        key = (row["run_id"], row["waf"], row["test_id"])
        if key in seen:
            raise ValueError(f"Duplicate result key: {key}")
        seen.add(key)
        if not all(row[k] for k in ("run_id", "waf", "test_id", "request_id", "test_set_sha256", "case_sha256")):
            raise ValueError("Result row is missing run/case provenance.")
        timestamp = datetime.fromisoformat(row["timestamp"])
        if timestamp.tzinfo is None:
            raise ValueError("Results require timezone-aware collection timestamps.")
        if row["execution_status"] not in ("SENT", "ERROR", "SKIPPED"):
            raise ValueError("Invalid execution_status.")
        if row["execution_status"] != "SENT" and row["waf_action"] != "UNKNOWN":
            raise ValueError("Failed or skipped requests must remain UNKNOWN.")
        if row["execution_status"] == "SENT":
            if not row["http_status"].isdigit() or not 100 <= int(row["http_status"]) <= 599:
                raise ValueError("A sent result requires a valid HTTP status.")
        if row["waf_action"] != "UNKNOWN" and not row["evidence_reference"].strip():
            raise ValueError("Known WAF actions require an evidence reference.")
        if row["classification"] != classify(row["expected_class"], row["waf_action"]):
            raise ValueError(f"Inconsistent classification for {row['test_id']}.")
    return rows

def one_condition(rows: list[dict]) -> None:
    if len({(r["run_id"], r["waf"], r["test_set_sha256"]) for r in rows}) != 1:
        raise ValueError("Supply one run, one WAF and one test-set digest per analysis.")
