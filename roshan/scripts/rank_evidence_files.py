#!/usr/bin/env python3

import csv
import subprocess
from pathlib import Path

BRANCHES = [
    "main",
    "Tools-Attack-Lead",
    "bishal-weekly-evidence",
    "comp6016-controlled-testing",
    "integrate-tools-attack-lead",
    "r11-r12-waf-evaluation",
    "role4",
]

EXTENSIONS = {
    ".csv": 5,
    ".json": 5,
    ".jsonl": 5,
    ".xlsx": 5,
    ".txt": 3,
    ".md": 2,
}

KEYWORDS = {
    "result": 5,
    "results": 5,
    "summary": 5,
    "comparison": 5,
    "metrics": 5,
    "confusion": 5,
    "detection": 5,
    "validation": 5,
    "evaluation": 5,
    "performance": 5,
    "false_positive": 5,
    "false_negative": 5,
    "missed": 5,
    "attack": 3,
    "payload": 3,
    "sqli": 4,
    "sql": 3,
    "xss": 4,
    "command": 4,
    "traversal": 4,
    "xml": 4,
    "xpath": 4,
    "server": 3,
    "benign": 4,
    "waf": 3,
}

OUTPUT = Path("roshan/evidence/evidence_candidates.csv")


def files_for_branch(branch):
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", f"origin/{branch}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.splitlines()


def score(path):
    lower = path.lower()
    suffix = Path(path).suffix.lower()

    if suffix not in EXTENSIONS:
        return 0

    value = EXTENSIONS[suffix]

    for keyword, points in KEYWORDS.items():
        if keyword in lower:
            value += points

    # Prefer files that look like actual result/data files
    if any(x in lower for x in [
        "/results/",
        "/result/",
        "/analysis/",
        "/metrics/",
        "/validation/",
        "/evidence/",
    ]):
        value += 6

    # Screenshots and generic documentation are lower priority
    if "/screenshots/" in lower:
        value -= 8

    if suffix == ".md" and "report" in lower:
        value -= 2

    return value


rows = []

for branch in BRANCHES:
    print(f"Ranking {branch}...")

    for path in files_for_branch(branch):
        points = score(path)

        if points > 0:
            rows.append({
                "branch": branch,
                "score": points,
                "extension": Path(path).suffix.lower(),
                "path": path,
            })

rows.sort(
    key=lambda r: (-int(r["score"]), r["branch"], r["path"])
)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["branch", "score", "extension", "path"]
    )
    writer.writeheader()
    writer.writerows(rows)

print()
print(f"Evidence candidates written to: {OUTPUT}")
print(f"Candidate files: {len(rows)}")
