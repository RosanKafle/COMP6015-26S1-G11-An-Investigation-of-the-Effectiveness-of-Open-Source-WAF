# Submission Index

Use this file as the supervisor-facing map of the project folder.

## Start Here

- `SUPERVISOR_START_HERE.md` gives the recommended review order.
- `README.md` explains how to run the framework and regenerate analysis.
- `REPORT_PACKAGE_INDEX.md` lists the report-ready evidence package.
- `RESULTS_INDEX.md` lists completed and missing experiment datasets.
- `ANALYSIS_GUIDE.md` explains the generated analysis tables.

## Recommended Review Order

1. `reports/final/` - final or near-final Word report documents.
2. `analysis/final/report_summary.md` - report-ready summary tables.
3. `analysis/final/key_findings.txt` - short generated findings.
4. `analysis/final/*.csv` - final analysis tables used in the report.
5. `output/` - raw structured automated experiment evidence.
6. `evidence/manual_validation/` - manually validated SQLi and CSRF evidence.
7. `docs/` - weekly historical evidence and cleaned evidence notes.
8. `framework/`, `tools/`, and `scripts/` - reproducibility source code.

## Folder Layout

- `framework/` - Python source code for the WAF evaluation framework.
- `output/` - raw structured experiment runs in nested environment/phase/load folders.
- `analysis/final/` - authoritative final CSV/Markdown analysis outputs.
- `analysis/archive/` - superseded analysis material retained for traceability.
- `reports/` - Word report files and table-only report exports.
- `docs/` - historical weekly evidence and cleaned evidence notes.
- `evidence/` - manual validation evidence plus optional screenshots, logs, and notes.
- `scripts/` - repository validation and coverage helper scripts.
- `submission/` - packaged submission archives.
- `archive/` - old or duplicate files kept for traceability.

## Primary Evidence Chain

```text
reports/final/
  -> analysis/final/
    -> output/<environment>/<phase>/<load_level>/run_<run_id>/
```

Manual validation evidence:

```text
evidence/manual_validation/results/
  -> evidence/manual_validation/payloads/
  -> tools/manual_validation/
```

## Do Not Submit as Evidence

The following are local/generated files only and should not be treated as report evidence:

- `.git/`
- `.venv/`
- `__pycache__/`
- `.DS_Store`
- Word lock files beginning with `~$`

Run this before submission:

```bash
python3 scripts/validate_structure.py
python3 scripts/list_experiment_coverage.py
```
