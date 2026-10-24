"""Report observed CRS activations and multi-label category matches from real logs."""
import argparse
from collections import Counter
import csv
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from result_reader import read_results, one_condition
from parse_modsecurity_audit import EVENT_FIELDS
from result_writer import write_json

GROUPS = {"941": "xss", "942": "sqli", "930": "path_traversal", "932": "command_injection"}

def analyse(raw, events_file, output):
    rows = read_results(raw)
    one_condition(rows)
    lookup = {(r["run_id"], r["waf"], r["test_id"], r["request_id"]): r for r in rows}
    counts, categories = Counter(), {}
    with events_file.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or set(EVENT_FIELDS) - set(reader.fieldnames):
            raise ValueError("Expected rule_events.csv produced from actual audit transactions.")
        events = list(reader)
    seen = set()
    for event in events:
        key = tuple(event[k] for k in ("run_id", "waf", "test_id", "request_id"))
        if key not in lookup or not event["evidence_reference"]:
            raise ValueError("Unmatched event or missing evidence.")
        identity = (key, event["transaction_id"], event["rule_id"], event["evidence_reference"])
        if identity in seen:
            raise ValueError("Duplicate rule event.")
        seen.add(identity)
        counts[event["rule_group"]] += 1
        if event["rule_group"] in GROUPS:
            categories.setdefault(key, set()).add(GROUPS[event["rule_group"]])
    output.mkdir(parents=True, exist_ok=False)
    with (output / "rule_group_summary.csv").open("x", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["rule_group", "observed_activations", "request_count"])
        for group, count in sorted(counts.items()):
            affected = {e["request_id"] for e in events if e["rule_group"] == group}
            writer.writerow([group, count, len(affected)])
    with (output / "attack_classification.csv").open("x", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["test_id", "expected_category", "observed_crs_categories", "interpretation"])
        for key, row in lookup.items():
            detected = categories.get(key, set())
            writer.writerow([row["test_id"], row["category"], ";".join(sorted(detected)),
                             "MULTIPLE_RULE_CATEGORIES" if len(detected)>1 else
                             "RULE_CATEGORY_OBSERVED" if detected else "NO_CATEGORY_EVIDENCE"])
    write_json(output / "limitations.json", {
        "note": "Rule activations are not unique blocked requests. Category is observed from rule IDs, never copied from the expected label. Missing events do not prove allowance. NAXSI scores have different semantics."})

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--events", type=Path, required=True)
    p.add_argument("--output-directory", type=Path, required=True)
    a = p.parse_args()
    try:
        analyse(a.input, a.events, a.output_directory)
    except (ValueError, OSError) as exc:
        p.exit(2, f"{exc}\n")
if __name__ == "__main__":
    main()
