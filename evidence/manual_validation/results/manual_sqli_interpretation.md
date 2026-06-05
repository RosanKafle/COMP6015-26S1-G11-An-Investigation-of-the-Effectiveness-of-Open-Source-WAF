# Manual SQL Injection Payload Testing Summary

## Purpose

Manual SQL injection testing was added to supplement the automated WAF evaluation results. The goal was to identify not only how many SQLi requests were blocked, but which SQLi payload patterns were blocked or not cleanly blocked by each WAF.

## Payload source and selection

The SQLi payloads were selected from common SQL injection pattern categories represented in PayloadsAllTheThings, including:

- Entry-point detection
- Boolean-based injection
- UNION-based injection
- Error-based injection
- No-space/comment obfuscation
- Case modification
- URL encoding
- Plus-as-space encoding
- Time-based probing

Only a small controlled payload set was used so that each payload could be manually interpreted.

## Overall results

| Environment | Sent | Clean blocked | Allowed | Server errors | Detection rate | Allowed rate |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | 12 | 0 | 10 | 2 | 0.00% | 83.33% |
| ModSecurity | 12 | 10 | 0 | 2 | 83.33% | 0.00% |
| Coraza | 12 | 10 | 0 | 2 | 83.33% | 0.00% |

## Interpretation

The baseline/no-WAF environment allowed 10 of 12 SQLi payloads, confirming that the DVWA SQLi endpoint was vulnerable without WAF protection. The two remaining baseline requests caused HTTP 500 server errors and were not counted as blocks.

ModSecurity and Coraza each cleanly blocked 10 of 12 SQLi payloads. The cleanly blocked payloads included boolean-based SQLi, UNION-based SQLi, comment-obfuscated SQLi, case-modified SQLi, URL-encoded SQLi, plus-as-space SQLi, and time-based SQLi.

The two payloads that were not cleanly blocked under both WAFs were:

| Payload ID | Attack subtype | Evasion type | Payload | Status | Classification |
|---|---|---|---|---:|---|
| SQLI001 | entry_point_detection | single_quote | `'` | 500 | server_error_not_clean_block |
| SQLI005 | error_based | basic_error | `1'` | 500 | server_error_not_clean_block |

These two cases were not counted as WAF detections because they returned HTTP 500 rather than a clean WAF block response. In this project, only HTTP 403, 406, and 501 were treated as clean WAF blocks. HTTP 500 responses were classified separately as server errors or disruption.

## Evidence files

- `manual_tests/payloads/manual_sqli_payloads.csv`
- `manual_tests/results/baseline_manual_sqli.csv`
- `manual_tests/results/modsec_manual_sqli.csv`
- `manual_tests/results/coraza_manual_sqli.csv`
- `manual_tests/results/manual_sqli_overall_summary.csv`
- `manual_tests/results/manual_sqli_summary.csv`
- `manual_tests/results/manual_sqli_missed_by_waf.csv`
- `manual_tests/results/manual_sqli_blocked_by_waf.csv`
