"""Extract only evidence-supported false-negative rows."""
import argparse
import csv
from pathlib import Path
from metrics import read_results, one_condition

FIELDS = ["run_id", "waf", "test_id", "parent_test_id", "category", "variant",
          "transformation", "payload", "http_status", "waf_action", "notes"]

def extract(rows: list[dict], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            if row["classification"] == "FN":
                writer.writerow({k: row[k] for k in FIELDS})

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "results/processed/missed_detections.csv")
    args = parser.parse_args()
    try:
        rows = read_results(args.input)
        one_condition(rows)
        extract(rows, args.output)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"{exc}\n")

if __name__ == "__main__":
    main()
