"""Generate reviewable variants without overwriting baseline files or existing variants."""
import argparse
import csv
from dataclasses import asdict, fields
from pathlib import Path
from payload_variants import TRANSFORMATIONS, transform_case
from test_loader import ROOT, TestCase, load_tests

def generate(directory: Path, output: Path, transforms: list[str]) -> int:
    if output.resolve().parent != (directory / "variants").resolve():
        raise ValueError("Variant output must be inside test_cases/variants.")
    if len(transforms) != len(set(transforms)):
        raise ValueError("Duplicate transformations requested.")
    cases = load_tests(directory)
    generated = []
    for case in cases:
        for name in transforms:
            variant = transform_case(case, name)
            if variant:
                generated.append(variant)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[f.name for f in fields(TestCase)])
        writer.writeheader()
        writer.writerows(asdict(c) for c in generated)
    return len(generated)

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "test_cases")
    parser.add_argument("--output", type=Path, default=ROOT / "test_cases/variants/generated_variants.csv")
    parser.add_argument("--transformations", nargs="+", choices=TRANSFORMATIONS, default=list(TRANSFORMATIONS))
    args = parser.parse_args()
    try:
        count = generate(args.directory, args.output, args.transformations)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"Variant generation failed: {exc}\n")
    print(f"Generated {count} candidate variants; all require review before execution.")

if __name__ == "__main__":
    main()
