"""Join researcher-reviewed WAF/backend evidence without editing raw observations."""
import argparse
import csv
from pathlib import Path
from classification import classify
from result_reader import read_results
from result_writer import FIELDS, sha256, write_json

EVIDENCE_FIELDS = ["run_id", "waf", "test_id", "request_id", "waf_action", "evidence_reference", "notes"]

def apply(raw: Path, evidence: Path, output: Path) -> None:
    rows = read_results(raw)
    with evidence.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or set(EVIDENCE_FIELDS) - set(reader.fieldnames):
            raise ValueError("Evidence CSV requires: " + ", ".join(EVIDENCE_FIELDS))
        decisions = {}
        for item in reader:
            if None in item or any(v is None for v in item.values()):
                raise ValueError("Malformed evidence row.")
            key = tuple(item[k] for k in EVIDENCE_FIELDS[:4])
            if key in decisions:
                raise ValueError("Duplicate evidence decision.")
            if item["waf_action"] not in ("BLOCKED", "ALLOWED", "UNKNOWN"):
                raise ValueError("Invalid evidence action.")
            if not item["evidence_reference"].strip() or not item["notes"].strip():
                raise ValueError("Each decision requires a log reference and review rationale.")
            if item["notes"].startswith("CANDIDATE:"):
                raise ValueError("Unreviewed block candidate; inspect the actual transaction and replace the candidate note with a review rationale.")
            decisions[key] = item
    if not decisions:
        raise ValueError("No reviewed evidence supplied.")
    existing = {tuple(r[k] for k in EVIDENCE_FIELDS[:4]) for r in rows}
    if decisions.keys() - existing:
        raise ValueError("Evidence refers to a different run/request; join refused.")
    for row in rows:
        decision = decisions.get(tuple(row[k] for k in EVIDENCE_FIELDS[:4]))
        if decision:
            if row["execution_status"] != "SENT":
                raise ValueError("Cannot classify a skipped or failed request.")
            row["waf_action"] = decision["waf_action"]
            row["classification"] = classify(row["expected_class"], row["waf_action"])
            row["evidence_reference"] = decision["evidence_reference"]
            row["notes"] += " Evidence review: " + decision["notes"]
    if raw.resolve() == output.resolve():
        raise ValueError("Never overwrite raw results.")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    write_json(output.with_suffix(".provenance.json"), {
        "raw_file": str(raw.resolve()), "raw_sha256": sha256(raw.read_bytes()),
        "evidence_file": str(evidence.resolve()), "evidence_sha256": sha256(evidence.read_bytes()),
        "enriched_sha256": sha256(output.read_bytes()),
        "note": "Researcher assertions require independently retained real logs; this join does not authenticate them."
    })

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        apply(args.raw, args.evidence, args.output)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"Evidence join failed: {exc}\n")

if __name__ == "__main__":
    main()
