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

KEYWORDS = [
    "sqli",
    "sql",
    "xss",
    "command",
    "cmd",
    "traversal",
    "inclusion",
    "upload",
    "xml",
    "xpath",
    "xxe",
    "server",
    "rce",
    "false",
    "benign",
    "performance",
    "latency",
    "result",
    "summary",
    "comparison",
    "validation",
    "evidence",
    "payload",
    "attack",
    "waf",
]

OUTPUT = Path("roshan/evidence/repository_inventory.csv")


def get_files(branch):
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", f"origin/{branch}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.splitlines()


def relevant(path):
    lower = path.lower()
    return any(keyword in lower for keyword in KEYWORDS)


rows = []

for branch in BRANCHES:
    print(f"Scanning origin/{branch}...")

    for path in get_files(branch):
        if relevant(path):
            rows.append({
                "branch": branch,
                "path": path,
            })


OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["branch", "path"]
    )
    writer.writeheader()
    writer.writerows(rows)

print()
print(f"Inventory written to: {OUTPUT}")
print(f"Relevant files found: {len(rows)}")
