#!/usr/bin/env python3

import csv
import subprocess
from collections import defaultdict
from pathlib import Path

CONTRIBUTION_ROOT = Path(__file__).resolve().parents[1]
INPUT = CONTRIBUTION_ROOT / "evidence/repository_inventory.csv"
OUTPUT = CONTRIBUTION_ROOT / "evidence/source_version_matrix.csv"

BRANCHES = [
    "main",
    "Tools-Attack-Lead",
    "bishal-weekly-evidence",
    "comp6016-controlled-testing",
    "integrate-tools-attack-lead",
    "r11-r12-waf-evaluation",
    "role4",
]

# Focus on actual experimental/result files.
KEYWORDS = [
    "summary",
    "results",
    "result",
    "metrics",
    "comparison",
    "detection",
    "missed",
    "classification",
    "validation",
    "performance",
    "confusion",
    "attack_category",
]

EXTENSIONS = {
    ".csv",
    ".json",
    ".jsonl",
    ".xlsx",
    ".txt",
}


def blob_hash(branch, path):
    result = subprocess.run(
        ["git", "rev-parse", f"origin/{branch}:{path}"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return ""

    return result.stdout.strip()


with INPUT.open(newline="") as f:
    rows = list(csv.DictReader(f))

paths = defaultdict(set)

for row in rows:
    path = row["path"]
    lower = path.lower()
    suffix = Path(path).suffix.lower()

    if suffix not in EXTENSIONS:
        continue

    if any(keyword in lower for keyword in KEYWORDS):
        paths[path].add(row["branch"])


results = []

for path, branches in sorted(paths.items()):
    hashes = {}

    for branch in sorted(branches):
        h = blob_hash(branch, path)

        if h:
            hashes[branch] = h

    unique_hashes = set(hashes.values())

    if len(hashes) >= 2:
        status = "IDENTICAL" if len(unique_hashes) == 1 else "DIFFERENT"

        results.append({
            "path": path,
            "branches": ";".join(sorted(hashes)),
            "branch_count": len(hashes),
            "unique_versions": len(unique_hashes),
            "status": status,
            "hashes": ";".join(
                f"{branch}:{value}"
                for branch, value in sorted(hashes.items())
            ),
        })


OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "path",
            "branches",
            "branch_count",
            "unique_versions",
            "status",
            "hashes",
        ],
    )
    writer.writeheader()
    writer.writerows(results)

print(f"Source comparison written to {OUTPUT}")
print(f"Files compared: {len(results)}")
print(
    "Different versions:",
    sum(1 for r in results if r["status"] == "DIFFERENT"),
)
print(
    "Identical versions:",
    sum(1 for r in results if r["status"] == "IDENTICAL"),
)
