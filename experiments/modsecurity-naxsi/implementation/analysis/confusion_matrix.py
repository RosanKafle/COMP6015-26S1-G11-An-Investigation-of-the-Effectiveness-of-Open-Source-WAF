"""Write a count matrix only from validated real observations."""
import argparse
import csv
from pathlib import Path
from metrics import calculate, one_condition, read_results

def matrix(rows: list[dict], output: Path) -> None:
    metrics = calculate(rows)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["expected_class", "BLOCKED", "ALLOWED", "UNKNOWN"])
        for expected, blocked, allowed in (("MALICIOUS", "TP", "FN"), ("NORMAL", "FP", "TN")):
            writer.writerow([expected, metrics[blocked], metrics[allowed],
                             sum(r["expected_class"] == expected and r["classification"] == "UNKNOWN" for r in rows)])

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "results/processed/confusion_matrix.csv")
    args = parser.parse_args()
    try:
        rows = read_results(args.input)
        one_condition(rows)
        matrix(rows, args.output)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"{exc}\n")

if __name__ == "__main__":
    main()
