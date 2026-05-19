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

- `analysis/report_summary.md` — report-ready summary tables
- `analysis/final_attack_type_summary.csv` — detection by attack type
- `analysis/final_benign_summary.csv` — benign traffic and false positive results
- `analysis/final_waf_comparison.csv` — comparison between WAFs

## Raw evidence files

- `output/baseline_attack_only.csv`
- `output/modsec_attack_only.csv`
- `output/coraza_attack_only.csv`
- `output/baseline_mixed_medium.csv`
- `output/modsec_mixed_medium.csv`
- `output/coraza_mixed_medium.csv`

## Key interpretation

Mixed traffic means benign live traffic was introduced while attack traffic was also running. This was used to test whether detection accuracy, false positives, latency, and stability changed under more realistic conditions.

NAXSI results are not included in this dataset unless added separately by another team member.
