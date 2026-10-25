"""Calculate counts and rates from a supplied real result CSV; never fill missing data."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from result_reader import one_condition, read_results

def divide(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None

def calculate(rows: list[dict]) -> dict:
    count = Counter(r["classification"] for r in rows)
    tp, tn, fp, fn = (count[k] for k in ("TP", "TN", "FP", "FN"))
    return dict(TP=tp, TN=tn, FP=fp, FN=fn, UNKNOWN=count["UNKNOWN"],
                total_rows=len(rows), sent=sum(r["execution_status"] == "SENT" for r in rows),
                errors=sum(r["execution_status"] == "ERROR" for r in rows),
                skipped=sum(r["execution_status"] == "SKIPPED" for r in rows),
                detection_rate=divide(tp, tp + fn), false_negative_rate=divide(fn, tp + fn),
                false_positive_rate=divide(fp, fp + tn), normal_allow_rate=divide(tn, tn + fp))

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        rows = read_results(args.input)
        one_condition(rows)
        result = calculate(rows)
        rendered = json.dumps(result, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(rendered + "\n")
        print(rendered)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"{exc}\n")

if __name__ == "__main__":
    main()
