# WAF Evaluation Results Index

## Purpose

This folder contains automated empirical testing results for the project:

**An Investigation of the Effectiveness of Open-Source Web Application Firewalls**

The data compares:

- Baseline / No WAF
- ModSecurity
- Coraza

NAXSI is not included in this dataset unless added separately by another team member.

---

## Experiment modes

### Attack-only

Only controlled malicious traffic was sent. This measures direct WAF detection effectiveness.

### Mixed traffic

Benign live traffic and malicious attack traffic were sent at the same time. This measures WAF behaviour under more realistic traffic conditions.

---

## Main files for report writing

Use these first:

- `analysis/report_summary.md`
- `analysis/final_attack_type_summary.csv`
- `analysis/final_benign_summary.csv`
- `analysis/final_waf_comparison.csv`

---

## Raw evidence files

Attack-only:

- `output/baseline_attack_only.csv`
- `output/modsec_attack_only.csv`
- `output/coraza_attack_only.csv`

Mixed traffic:

- `output/baseline_mixed_medium.csv`
- `output/modsec_mixed_medium.csv`
- `output/coraza_mixed_medium.csv`

---

## Key metrics

The analysis includes:

- Total attack requests
- Detection rate
- False negative rate
- False positive rate
- Average response latency
- Detection change under mixed traffic
- Performance impact

---

## Current key findings

- Coraza showed higher detection rates than ModSecurity for SQL injection, XSS, brute-force, and JavaScript-related tests.
- Neither ModSecurity nor Coraza blocked benign traffic in the tested dataset, producing a 0.00% false positive rate.
- Coraza maintained stable detection under mixed traffic.
- ModSecurity mixed-traffic detection showed an unexpected drop and should be verified with a repeat run before being treated as a final conclusion.
- Logic-based weaknesses such as CSRF, weak session IDs, and authorization bypass were not meaningfully blocked by either WAF.
