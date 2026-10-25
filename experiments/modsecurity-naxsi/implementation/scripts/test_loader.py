"""Load, validate and count a modest, deterministic laboratory corpus."""
from __future__ import annotations
import argparse
import csv
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from lab_http import validate_endpoint

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = ["test_id", "category", "variant", "method", "endpoint", "parameter",
            "payload", "expected_class", "description"]
CATEGORIES = ("normal", "sqli", "xss", "command_injection", "path_traversal")

@dataclass(frozen=True)
class TestCase:
    test_id: str
    category: str
    variant: str
    method: str
    endpoint: str
    parameter: str
    payload: str
    expected_class: str
    description: str
    parent_test_id: str = ""
    transformation: str = ""
    wire_encoding: str = "form"
    review_status: str = "BASELINE"

def load_tests(directory: Path, include_variants: bool = False) -> list[TestCase]:
    files = sorted(directory.glob("*.csv"))
    if include_variants:
        files += sorted((directory / "variants").glob("*.csv"))
    if not files:
        raise ValueError(f"No test-case CSV files found in {directory}.")
    tests = []
    seen = set()
    for path in files:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or set(REQUIRED) - set(reader.fieldnames):
                raise ValueError(f"{path.name}: missing required columns.")
            if len(reader.fieldnames) != len(set(reader.fieldnames)):
                raise ValueError(f"{path.name}: duplicate columns.")
            if set(reader.fieldnames) - set(TestCase.__dataclass_fields__):
                raise ValueError(f"{path.name}: unsupported columns.")
            for number, row in enumerate(reader, 2):
                if None in row or any(v is None for v in row.values()):
                    raise ValueError(f"{path.name}:{number}: malformed CSV row.")
                case = TestCase(**row)
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", case.test_id):
                    raise ValueError(f"{path.name}:{number}: invalid test ID.")
                if case.test_id in seen:
                    raise ValueError(f"Duplicate test ID: {case.test_id}")
                seen.add(case.test_id)
                if case.category not in CATEGORIES or case.expected_class not in ("NORMAL", "MALICIOUS"):
                    raise ValueError(f"{case.test_id}: invalid category or expected class.")
                if (case.category == "normal") != (case.expected_class == "NORMAL"):
                    raise ValueError(f"{case.test_id}: category and expected class conflict.")
                if case.method not in ("GET", "POST"):
                    raise ValueError(f"{case.test_id}: method must be GET or POST.")
                validate_endpoint(case.endpoint)
                if not case.variant or not case.description or (not case.parameter and case.category != "normal"):
                    raise ValueError(f"{case.test_id}: variant, description and parameter are required.")
                if case.wire_encoding not in ("form", "preencoded"):
                    raise ValueError(f"{case.test_id}: unsupported wire encoding.")
                if case.review_status not in ("BASELINE", "REQUIRES_REVIEW", "APPROVED"):
                    raise ValueError(f"{case.test_id}: invalid review_status.")
                if bool(case.parent_test_id) != bool(case.transformation):
                    raise ValueError(f"{case.test_id}: parent and transformation must occur together.")
                if case.parent_test_id and case.review_status == "BASELINE":
                    raise ValueError(f"{case.test_id}: variants need a review decision.")
                if case.wire_encoding == "preencoded" and (
                    re.search(r"%(?![0-9A-Fa-f]{2})", case.payload)
                    or re.search(r"[^A-Za-z0-9_.~%\-]", case.payload)
                ):
                    raise ValueError(f"{case.test_id}: unsafe preencoded parameter.")
                tests.append(case)
    baseline = {t.test_id: t for t in tests if not t.parent_test_id}
    for case in tests:
        if case.parent_test_id:
            parent = baseline.get(case.parent_test_id)
            if parent is None:
                raise ValueError(f"{case.test_id}: baseline parent is missing.")
            if any(getattr(case, key) != getattr(parent, key) for key in
                   ("category", "expected_class", "method", "endpoint", "parameter")):
                raise ValueError(f"{case.test_id}: variant changes parent routing or classification.")
    return tests

def inventory(tests: list[TestCase], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    counts = Counter(t.category for t in tests)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["category", "count", "placeholder_cases"])
        for category, count in sorted(counts.items()):
            writer.writerow([category, count, sum(
                t.category == category and t.payload.startswith("PLACEHOLDER") for t in tests)])
    print(f"Validated {len(tests)} cases: {dict(sorted(counts.items()))}")

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "test_cases")
    parser.add_argument("--include-variants", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/test_inventory.csv")
    args = parser.parse_args()
    try:
        inventory(load_tests(args.directory, args.include_variants), args.output)
    except (OSError, ValueError, TypeError, csv.Error) as exc:
        parser.exit(2, f"Test-set error: {exc}\n")

if __name__ == "__main__":
    main()
