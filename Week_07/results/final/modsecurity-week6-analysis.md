# Initial analysis

## 1. Experiment information

- Run: 20260922T081541Z_d78b12c20b69
- WAF: modsecurity
- Source: `Week_07/results/final/modsecurity-week6-reviewed.csv`
- Source SHA-256: 7f623fc70fa9a61e82c895dd0f6221d437f35be63babc60e719d0a0b056f949d
- Test-set SHA-256: 78123abfcb920965749a0877a3d1f6e28126e339b6ae66acf589eec5dc1a10d7
- Collection timestamps: 2026-09-22T08:15:42.038221+00:00 to 2026-09-22T08:19:15.539136+00:00
- Report generated: 2026-09-22T10:54:42.653726+00:00

## 2. Number of tests

Rows: 1684; HTTP responses: 1684; errors: 0; skipped: 0.
Unclassified rows: 0. Skipped rows are not executed trials.

## 3. Normal traffic

Rows: 120; TN: 109; FP: 11.
False-positive rate: 0.09166666666666666.
Normal allow rate: 0.9083333333333333.

## 4. Malicious traffic

Rows: 1564; TP: 1564; FN: 0.
Detection rate: 1.0.
False-negative rate: 0.0.

## 5. Overall confusion matrix

| Expected | BLOCKED | ALLOWED |
|---|---:|---:|
| MALICIOUS | 1564 | 0 |
| NORMAL | 11 | 109 |

UNKNOWN (0) is excluded from matrix rates, not converted to FN/TN.

## 6. Per-category detection

| Category | HTTP responses | Blocked | Allowed | Unknown responses | Errors | Skipped | Detection rate |
|---|---:|---:|---:|---:|---:|---:|---|
| command_injection | 120 | 120 | 0 | 0 | 0 | 0 | 1.0 |
| path_traversal | 120 | 120 | 0 | 0 | 0 | 0 | 1.0 |
| sqli | 724 | 724 | 0 | 0 | 0 | 0 | 1.0 |
| xss | 600 | 600 | 0 | 0 | 0 | 0 | 1.0 |

## 7. Missed detections

No evidence-supported FN rows in this input. This is not proof of perfect protection.

## 8. Baseline vs obfuscated comparison

- candidate_rows: 1084
- classified_pairs: 1084
- blocked_to_allowed: 0
- allowed_to_blocked: 0
- unchanged: 1084
- unpaired_or_unknown: 0

These are within-run paired dispositions, not proof that every variation preserved attack semantics.

## 9. Limitations

Rates are fractions from 0 to 1 and use classified denominators only. Unknowns can bias the observed rates.
Human evidence references must be audited against retained logs. CSV validation cannot establish authenticity.
A WAF allowance is not proof of successful exploitation. Review application/session state and payload validity.
Lab engine versions, thresholds, repetitions, ordering and corpus representativeness limit generalisation.
Unreviewed cases/variants and unsupported XML scenarios provide no detection evidence.
No confidence intervals, population estimates, rule-cause claims or graphs are inferred automatically.
Baseline/variant rows are related observations; do not assume statistical independence.
