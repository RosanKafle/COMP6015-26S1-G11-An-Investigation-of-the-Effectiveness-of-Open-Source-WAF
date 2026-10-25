"""Per-category malicious disposition; unknowns are never converted to misses."""
import argparse
from collections import defaultdict
import csv
from pathlib import Path
from metrics import divide
from result_reader import one_condition, read_results

FIELDS = ["category", "total_malicious", "blocked_malicious", "allowed_malicious",
          "detection_rate", "unknown_sent_malicious", "errors", "skipped"]

def summarize(rows: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for row in rows:
        if row["expected_class"] == "MALICIOUS":
            groups[row["category"]].append(row)
    result = []
    for category, group in sorted(groups.items()):
        blocked = sum(r["classification"] == "TP" for r in group)
        allowed = sum(r["classification"] == "FN" for r in group)
        result.append(dict(
            category=category, total_malicious=sum(r["execution_status"] == "SENT" for r in group),
            blocked_malicious=blocked, allowed_malicious=allowed,
            detection_rate=divide(blocked, blocked + allowed),
            unknown_sent_malicious=sum(r["classification"] == "UNKNOWN" and r["execution_status"] == "SENT" for r in group),
            errors=sum(r["execution_status"] == "ERROR" for r in group),
            skipped=sum(r["execution_status"] == "SKIPPED" for r in group)))
    return result

def write_summary(rows: list[dict], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(summarize(rows))

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "results/processed/category_summary.csv")
    args = parser.parse_args()
    try:
        rows = read_results(args.input)
        one_condition(rows)
        write_summary(rows, args.output)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"{exc}\n")

if __name__ == "__main__":
    main()
