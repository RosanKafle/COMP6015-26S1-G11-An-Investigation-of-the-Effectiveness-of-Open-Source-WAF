"""Append real observations to a new run; preserve payload lineage from collection."""
import csv
import hashlib
import json
from pathlib import Path

FIELDS = ["run_id", "timestamp", "waf", "test_id", "category", "variant",
          "expected_class", "method", "endpoint", "http_status", "response_length",
          "waf_action", "classification", "notes", "parent_test_id", "transformation",
          "payload", "parameter", "wire_encoding", "review_status", "request_id",
          "test_set_sha256", "case_sha256", "response_file", "response_sha256",
          "request_file", "execution_status", "evidence_reference", "response_time_seconds"]

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def write_json(path: Path, data: dict | list) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)

class ResultWriter:
    """Flush each row so an interrupted run retains already collected observations."""
    def __init__(self, path: Path):
        self.handle = path.open("x", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.handle, fieldnames=FIELDS)
        self.writer.writeheader()
        self.handle.flush()

    def write(self, row: dict) -> None:
        self.writer.writerow(row)
        self.handle.flush()

    def close(self) -> None:
        self.handle.close()
