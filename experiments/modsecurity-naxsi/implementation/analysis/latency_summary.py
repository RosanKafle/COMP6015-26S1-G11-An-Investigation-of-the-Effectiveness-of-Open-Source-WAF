"""Summarise measured client response times; no invented throughput benchmarks."""
import argparse
import math
from pathlib import Path
import statistics
from metrics import read_results, one_condition
from result_writer import write_json

def summarise(rows):
    values = []
    for row in rows:
        if row["execution_status"] != "SENT":
            continue
        value = row.get("response_time_seconds", "")
        if value == "":
            continue
        value = float(value)
        if not math.isfinite(value) or value < 0:
            raise ValueError("Invalid measured response time.")
        values.append(value)
    ordered = sorted(values)
    return {"measured_responses": len(values),
            "median_seconds": statistics.median(values) if values else None,
            "p95_seconds": ordered[math.ceil(0.95 * len(values))-1] if values else None,
            "note": "Client timings include ZAP, network and application. Not isolated WAF overhead; concurrency/throughput benchmarking remains a separate experiment."}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    try:
        rows = read_results(a.input)
        one_condition(rows)
        a.output.parent.mkdir(parents=True, exist_ok=True)
        write_json(a.output, summarise(rows))
    except (ValueError, OSError) as exc:
        p.exit(2, f"{exc}\n")
if __name__ == "__main__":
    main()
