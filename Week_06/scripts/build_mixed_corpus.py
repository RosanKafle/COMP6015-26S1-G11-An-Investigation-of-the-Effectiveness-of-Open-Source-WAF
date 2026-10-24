"""Make the previous semester's 120-per-class mixed workload reproducible."""
import argparse
import csv
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ["test_id", "category", "variant", "method", "endpoint", "parameter",
          "payload", "expected_class", "description"]
CATEGORIES = ("normal", "sqli", "xss", "command_injection", "path_traversal")

def build(templates, output, per_class=120, seed=2026):
    if not 1 <= per_class <= 1000:
        raise ValueError("per-class must be 1..1000.")
    rng = random.Random(seed)
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for category in CATEGORIES:
        pool = [t for t in templates if t["category"] == category]
        if not pool:
            raise ValueError(f"No inherited templates for {category}.")
        for number in range(per_class):
            template = rng.choice(pool)
            rows.append(dict(test_id=f"{category.upper()}_{number+1:04}", category=category,
                             variant="baseline", method=template["method"], endpoint=template["endpoint"],
                             parameter=template["parameter"], payload=template["payload"],
                             expected_class="NORMAL" if category == "normal" else "MALICIOUS",
                             description=f"Inherited template {template['source_id']}; " + template["change"]))
    # Stable shuffled CSV order replaces random.shuffle without a recorded seed.
    rng.shuffle(rows)
    with (output / "mixed.csv").open("x", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    (output / "corpus_manifest.json").write_text(json.dumps({
        "seed": seed, "per_class": per_class, "count": len(rows),
        "note": "Generated test inputs, not experimental results; repeated templates are not independent payloads."
    }, indent=2))
    return rows

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--templates", type=Path, default=ROOT / "config/inherited_test_templates.json")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--per-class", type=int, default=120)
    p.add_argument("--seed", type=int, default=2026)
    args = p.parse_args()
    try:
        rows = build(json.loads(args.templates.read_text()), args.output, args.per_class, args.seed)
        print(f"Prepared {len(rows)} input rows; no requests sent.")
    except (ValueError, OSError) as exc:
        p.exit(2, f"{exc}\n")

if __name__ == "__main__":
    main()
