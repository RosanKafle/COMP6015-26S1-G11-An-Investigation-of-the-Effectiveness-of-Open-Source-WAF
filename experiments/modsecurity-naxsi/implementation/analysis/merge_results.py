"""Match one ModSecurity and one NAXSI run only when their selected corpora match."""
import argparse
import csv
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from result_reader import one_condition, read_results
from result_writer import sha256, write_json

FIELDS = ["test_id", "category", "variant", "modsecurity_action", "naxsi_action",
          "modsecurity_classification", "naxsi_classification"]

def merge(modsecurity: Path, naxsi: Path, output: Path) -> None:
    left, right = read_results(modsecurity), read_results(naxsi)
    one_condition(left)
    one_condition(right)
    if {r["waf"] for r in left} != {"modsecurity"} or {r["waf"] for r in right} != {"naxsi"}:
        raise ValueError("Inputs must be correctly labelled ModSecurity and NAXSI runs.")
    if left[0]["test_set_sha256"] != right[0]["test_set_sha256"]:
        raise ValueError("Test-set digests differ; comparison would not use identical cases/order.")
    a, b = ({r["test_id"]: r for r in group} for group in (left, right))
    if a.keys() != b.keys():
        raise ValueError("Test IDs differ; incomplete runs cannot silently be merged.")
    records = []
    for test_id, row in a.items():
        other = b[test_id]
        if any(row[k] != other[k] for k in ("case_sha256", "category", "variant", "payload",
                "expected_class", "method", "endpoint", "parameter", "wire_encoding",
                "parent_test_id", "transformation")):
            raise ValueError(f"Case content differs for {test_id}.")
        records.append(dict(test_id=test_id, category=row["category"], variant=row["variant"],
                            modsecurity_action=row["waf_action"], naxsi_action=other["waf_action"],
                            modsecurity_classification=row["classification"],
                            naxsi_classification=other["classification"]))
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(records)
    write_json(output.with_suffix(".provenance.json"), {
        "modsecurity_source": str(modsecurity.resolve()), "modsecurity_sha256": sha256(modsecurity.read_bytes()),
        "naxsi_source": str(naxsi.resolve()), "naxsi_sha256": sha256(naxsi.read_bytes()),
        "test_set_sha256": left[0]["test_set_sha256"],
        "note": "Matching corpus does not prove matching lab settings; review run manifests and log evidence."
    })

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modsecurity", required=True, type=Path)
    parser.add_argument("--naxsi", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        merge(args.modsecurity, args.naxsi, args.output)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"Merge failed: {exc}\n")

if __name__ == "__main__":
    main()
