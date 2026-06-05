#!/usr/bin/env python3
"""List expected WAF experiment coverage from nested output folders."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "output"
EXPECTED = [
    ("baseline", "attack_only", "none"),
    ("baseline", "mixed", "medium"),
    ("modsec", "attack_only", "none"),
    ("modsec", "mixed", "medium"),
    ("coraza", "attack_only", "none"),
    ("coraza", "mixed", "medium"),
    ("naxsi", "attack_only", "none"),
    ("naxsi", "mixed", "medium"),
]


def main() -> int:
    rows = []
    for environment, phase, load_level in EXPECTED:
        path = OUTPUT_DIR / environment / phase / load_level
        runs = sorted(run for run in path.glob("run_*") if run.is_dir()) if path.exists() else []
        status = "available" if runs else "missing"
        rows.append((environment, phase, load_level, str(len(runs)), status))

    headers = ("Environment", "Phase", "Load Level", "Runs Found", "Status")
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    ]
    print(format_row(headers, widths))
    print(format_row(tuple("-" * width for width in widths), widths))
    for row in rows:
        print(format_row(row, widths))
    return 0


def format_row(row: tuple[str, ...], widths: list[int]) -> str:
    return " | ".join(value.ljust(widths[index]) for index, value in enumerate(row))


if __name__ == "__main__":
    raise SystemExit(main())
