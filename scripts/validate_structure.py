#!/usr/bin/env python3
"""Validate the repository layout and run-folder completeness."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_TOP_LEVEL = [
    "framework",
    "output",
    "analysis/final",
    "README.md",
    "ANALYSIS_GUIDE.md",
    "RESULTS_INDEX.md",
    "docs/README.md",
    "analysis/README.md",
    "analysis/final/README.md",
    "framework/README.md",
    "output/README.md",
    "reports/README.md",
    "reports/final",
    "scripts/README.md",
    "tools/README.md",
    "tools/manual_validation",
]
REQUIRED_RUN_FILES = [
    "detailed.csv",
    "summary.csv",
    "run_summary.json",
    "metadata.json",
    "validation.txt",
]
FORBIDDEN_NAMES = {
    ".DS_Store",
    "__pycache__",
}
FORBIDDEN_PREFIXES = (
    "~$",
)
SKIP_DIRS = {
    ".git",
    ".venv",
    ".cache",
}
MISPLACED_TOP_LEVEL_SUFFIXES = {
    ".docx",
    ".zip",
}


def main() -> int:
    missing: list[str] = []
    misplaced: list[str] = []
    for relative_path in REQUIRED_TOP_LEVEL:
        if not (ROOT / relative_path).exists():
            missing.append(relative_path)

    output_dir = ROOT / "output"
    for run_dir in sorted(output_dir.rglob("run_*")) if output_dir.exists() else []:
        if not run_dir.is_dir():
            continue
        for filename in REQUIRED_RUN_FILES:
            if not (run_dir / filename).exists():
                missing.append(str((run_dir / filename).relative_to(ROOT)))

    for path in ROOT.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name in FORBIDDEN_NAMES or path.name.startswith(FORBIDDEN_PREFIXES):
            misplaced.append(str(path.relative_to(ROOT)))

    for path in ROOT.iterdir():
        if path.is_file() and path.suffix.lower() in MISPLACED_TOP_LEVEL_SUFFIXES:
            misplaced.append(str(path.relative_to(ROOT)))

    if missing or misplaced:
        print("Repository structure validation: FAIL")
        if missing:
            print("Missing items:")
            for item in missing:
                print(f"- {item}")
        if misplaced:
            print("Misplaced or generated items:")
            for item in sorted(misplaced):
                print(f"- {item}")
        return 1

    print("Repository structure validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
