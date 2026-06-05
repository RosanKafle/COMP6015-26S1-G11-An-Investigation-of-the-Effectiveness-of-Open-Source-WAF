# WAF Evaluation Results Index

## Purpose

This repository contains automated and manual empirical testing results for the project:

**An Investigation of the Effectiveness of Open-Source Web Application Firewalls**

The data compares:

- Baseline / No WAF
- ModSecurity
- Coraza

NAXSI structured outputs are not present unless partner results are added separately.

## Experiment Modes

### Attack-only

Only controlled malicious traffic was sent. This measures direct WAF detection effectiveness.

### Mixed traffic

Benign live traffic and malicious attack traffic were sent at the same time. This measures WAF behaviour under more realistic traffic conditions.

## Main Files For Report Writing

Use these first:

- `analysis/final/report_summary.md`
- `analysis/final/key_findings.txt`
- `analysis/final/final_summary.csv`
- `analysis/final/final_attack_type_summary.csv`
- `analysis/final/final_benign_summary.csv`
- `analysis/final/final_waf_comparison.csv`
- `analysis/final/final_repetition_summary.csv`
- `analysis/final/final_classification_summary.csv`
- `analysis/final/final_classification_matrix.csv`

## Completed Raw Automated Runs

Each completed run is stored in:

```text
output/<environment>/<phase>/<load_level>/run_<run_id>/
```

Completed attack-only runs:

- `output/baseline/attack_only/none/run_20260519_063833/`
- `output/modsec/attack_only/none/run_20260519_064610/`
- `output/coraza/attack_only/none/run_20260519_074907/`

Completed mixed-traffic runs:

- `output/baseline/mixed/medium/run_20260519_074733/`
- `output/modsec/mixed/medium/run_20260519_033300_rerun/`
- `output/coraza/mixed/medium/run_20260519_064803/`

Each run folder contains:

- `detailed.csv`
- `summary.csv`
- `run_summary.json`
- `metadata.json`
- `validation.txt`

## Manual Validation Evidence

Manual SQLi and CSRF evidence is under:

- `evidence/manual_validation/payloads/`
- `evidence/manual_validation/results/`
- `evidence/manual_validation/results/manual_classification_summary.md`
- `evidence/manual_validation/ATTACK_TAXONOMY_AND_TEST_DESIGN.md`

## Key Metrics

The analysis includes:

- Total attack requests
- Detection rate
- False negative rate
- False positive rate
- Average response latency
- Detection change under mixed traffic
- Performance impact
- Manual clean-block recall for selected SQLi and CSRF validation cases

## Current Key Findings

- Coraza showed higher detection rates than ModSecurity for SQL injection, XSS, brute-force, and JavaScript-related tests.
- Neither ModSecurity nor Coraza blocked benign traffic in the tested dataset, producing a 0.00% false positive rate.
- Coraza maintained stable detection under mixed traffic.
- Logic-based weaknesses such as CSRF, weak session IDs, and authorization bypass were not meaningfully blocked by either WAF.
- Manual validation showed strong clean-block behaviour for selected SQLi payloads but weak semantic coverage for CSRF-style requests.

Run `python3 scripts/list_experiment_coverage.py` to print available and missing automated datasets.
