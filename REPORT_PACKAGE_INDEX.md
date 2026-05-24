# Report Evidence Package Index

This package is intended for report writing for:

**An Investigation of the Effectiveness of Open-Source Web Application Firewalls**

## Start Here

- `SUPERVISOR_START_HERE.md` - recommended supervisor review order
- `README.md` - how the framework is run
- `SUBMISSION_INDEX.md` - clean folder map for supervisor review
- `RESULTS_INDEX.md` - which datasets are present and missing
- `ANALYSIS_GUIDE.md` - how to interpret raw and final analysis files
- `analysis/final/report_summary.md` - report-ready tables
- `analysis/final/key_findings.txt` - short generated findings summary
- `reports/` - Word report documents and table-only report exports

## Final Empirical Results

Authoritative generated outputs are under `analysis/final/`.

- `analysis/final/final_summary.csv`
- `analysis/final/final_attack_type_summary.csv`
- `analysis/final/final_benign_summary.csv`
- `analysis/final/final_waf_comparison.csv`
- `analysis/final/final_repetition_summary.csv`
- `analysis/final/final_classification_matrix.csv`
- `analysis/final/final_classification_summary.csv`
- `analysis/final/confusion_matrices.csv`

## Report Documents

- `reports/final/COMP6015_Group11_WAF_Final_Report_SubmissionReady.docx` - submission-ready report version
- `reports/final/` - final or near-final Word report versions
- `reports/drafts/` - earlier report drafts
- `reports/tables/` - table-only exports and technical-note versions

## Raw Experiment Evidence

Structured runs are under:

```text
output/<environment>/<phase>/<load_level>/run_<run_id>/
```

Each run folder contains:

- `detailed.csv`
- `summary.csv`
- `run_summary.json`
- `metadata.json`
- `validation.txt`

## Manual Validation Evidence

Manual SQL injection and CSRF evidence is under:

- `evidence/manual_validation/README.md`
- `evidence/manual_validation/ATTACK_TAXONOMY_AND_TEST_DESIGN.md`
- `evidence/manual_validation/payloads/`
- `evidence/manual_validation/results/`

## Historical Weekly Evidence

Historical project material is under `docs/`.

Visible weekly folders in this repository start at:

- `docs/week3/`
- `docs/week4/`
- `docs/week5/`
- `docs/week6/`
- `docs/week7/`
- `docs/week8/`
- `docs/week9/`
- `docs/week10/`

Additional cleaned evidence is under:

- `docs/clean-evidence/`

Packaged archives, if needed, are under:

- `submission/packages/`

No dedicated `week1` or `week2` folders were present in this repository when the package was created.

## Missing Dataset Note

The completed structured experiment outputs currently cover Baseline, ModSecurity, and Coraza. NAXSI folders are placeholders unless partner results are added later.
