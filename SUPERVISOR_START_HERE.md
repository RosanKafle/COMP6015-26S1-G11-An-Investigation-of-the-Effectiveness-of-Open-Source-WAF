# Supervisor Start Here

This repository is the evidence package for:

**An Investigation of the Effectiveness of Open-Source Web Application Firewalls**

Use this file as the first navigation page when reviewing the submission.

## Recommended Review Order

1. Open `reports/final/COMP6015_Group11_WAF_Final_Report_SubmissionReady.docx` for the submission-ready report.
2. Open `analysis/final/report_summary.md` and `analysis/final/key_findings.txt` for the report-ready findings and tables.
3. Open `analysis/final/` for the CSV outputs used to support the report.
4. Open `output/` for the raw automated experiment runs behind the analysis.
5. Open `evidence/manual_validation/` for the manual SQL injection and CSRF validation evidence.
6. Open `docs/` for the historical weekly evidence trail and cleaned supporting notes.
7. Open `framework/` and `tools/` only if source-code or reproducibility details are needed.

## Folder Map

| Path | Purpose |
| --- | --- |
| `reports/final/` | Final or near-final Word report files. |
| `reports/drafts/` | Earlier report drafts retained for traceability. |
| `reports/tables/` | Word table exports and technical-note variants. |
| `analysis/final/` | Authoritative generated CSV and Markdown analysis outputs. |
| `output/` | Raw structured automated experiment evidence. |
| `evidence/manual_validation/` | Curated manual SQLi and CSRF payloads, raw results, and summaries. |
| `docs/clean-evidence/` | Cleaned baseline and early WAF evidence notes. |
| `docs/week*/` | Historical weekly exported tool outputs and notes. |
| `framework/` | Main Python experiment framework. |
| `tools/` | Supporting automated-framework and manual-validation scripts. |
| `scripts/` | Repository validation and coverage helper scripts. |
| `submission/` | Packaged archives prepared for supervisor upload. |
| `archive/` | Old or duplicate files retained only for traceability. |

## Evidence Traceability

The main evidence chain is:

```text
reports/final/
  -> analysis/final/
    -> output/<environment>/<phase>/<load_level>/run_<run_id>/
```

Manual validation follows a separate but documented chain:

```text
evidence/manual_validation/results/
  -> evidence/manual_validation/payloads/
  -> tools/manual_validation/
```

Historical supporting material is kept in:

```text
docs/clean-evidence/
docs/week3/ ... docs/week10/
```

## Known Boundaries

- Completed automated structured runs are present for Baseline, ModSecurity, and Coraza.
- NAXSI folders are placeholders unless partner results are added later.
- `archive/` is not primary evidence unless the report explicitly cites an archived file.
- Generated local files such as `.DS_Store`, `__pycache__/`, `.venv/`, and Word lock files are excluded from the submission evidence.

## Quick Validation

Run these commands from the repository root before submitting:

```bash
python3 scripts/validate_structure.py
python3 scripts/list_experiment_coverage.py
```
