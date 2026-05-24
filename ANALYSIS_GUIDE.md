# WAF Evaluation Data Guide

This folder contains automated empirical results for the WAF evaluation project.

## Environments tested

- Baseline / No WAF
- ModSecurity
- Coraza

## Test phases

### Attack-only
Only controlled malicious requests were sent.

### Mixed traffic
Controlled malicious requests were sent while benign live traffic was also generated.

## Main analysis files

- `analysis/final/report_summary.md` - report-ready summary tables.
- `analysis/final/key_findings.txt` - concise generated findings.
- `analysis/final/final_summary.csv` - per-environment summary metrics.
- `analysis/final/final_attack_type_summary.csv` - detection by attack type.
- `analysis/final/final_benign_summary.csv` - benign traffic and false positive results.
- `analysis/final/final_waf_comparison.csv` - comparison between WAFs.
- `analysis/final/final_classification_summary.csv` - detected attack classification summary.

## Raw evidence files

Raw automated evidence is stored in nested run folders:

```text
output/<environment>/<phase>/<load_level>/run_<run_id>/
```

Completed runs:

- `output/baseline/attack_only/none/run_20260519_063833/`
- `output/baseline/mixed/medium/run_20260519_074733/`
- `output/modsec/attack_only/none/run_20260519_064610/`
- `output/modsec/mixed/medium/run_20260519_033300_rerun/`
- `output/coraza/attack_only/none/run_20260519_074907/`
- `output/coraza/mixed/medium/run_20260519_064803/`

## Key interpretation

Mixed traffic means benign live traffic was introduced while attack traffic was also running. This was used to test whether detection accuracy, false positives, latency, and stability changed under more realistic conditions.

NAXSI results are not included in this dataset unless added separately by another team member.
