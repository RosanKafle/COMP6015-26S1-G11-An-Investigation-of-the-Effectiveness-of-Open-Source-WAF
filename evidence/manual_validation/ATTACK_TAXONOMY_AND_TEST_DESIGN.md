# Attack Taxonomy And Manual Test Design

This document explains the manually selected SQL injection and CSRF evidence in `evidence/manual_validation/`.

## Purpose

The manual validation set supplements the automated experiments in `output/`. It focuses on selected payloads where the WAF outcome needed closer interpretation than a bulk automated run can provide.

## Tested Families

| Family | Endpoint | Purpose |
| --- | --- | --- |
| SQL injection | `/vulnerabilities/sqli/` | Test signature-style WAF detection across common SQLi patterns and bypass variants. |
| CSRF-style password change | `/vulnerabilities/csrf/` | Test whether WAFs semantically detect CSRF-like state-changing requests. |

## SQL Injection Payload Classes

The expanded SQLi payload file groups tests into these classes:

- `entry_point_detection` - basic quote/probe payloads.
- `boolean_based` - true/false logical expressions.
- `union_based` - UNION SELECT style probes.
- `error_based` - payloads expected to cause SQL parser or application errors.
- `time_based` - sleep/delay probes.
- `waf_bypass` - encoded, spacing, case, comment, and separator variants.
- `mysql_specific` - MySQL-oriented payload patterns.
- `polyglot` - payloads combining multiple syntax styles.
- `auth_bypass` - authentication-bypass style strings adapted to the SQLi parameter.

Primary payload file:

- `payloads/manual_sqli_payloads_expanded.csv`

Primary result files:

- `results/manual_sqli_expanded_overall_summary.csv`
- `results/manual_sqli_expanded_by_pattern.csv`
- `results/manual_sqli_expanded_not_cleanly_blocked.csv`

## CSRF Test Classes

The CSRF tests use DVWA password-change requests with variations in password value and confirmation state:

- normal matching password change
- mismatched confirmation
- special characters
- long value
- missing confirmation

Primary payload file:

- `payloads/manual_csrf_tests.csv`

Primary result files:

- `results/manual_csrf_overall_summary.csv`
- `results/manual_csrf_summary.csv`
- `results/manual_csrf_non_clean_by_waf.csv`

## Outcome Classification

Only these status codes are counted as clean WAF blocks:

- HTTP 403
- HTTP 406
- HTTP 501

The following outcomes are preserved but are not counted as clean WAF detections:

- Redirects
- HTTP 500 server errors
- Application-level rejection without a WAF block status

This distinction matters because a WAF can disrupt an attack without clearly demonstrating correct security rule detection.

## Key Manual Summary

Use `results/manual_classification_summary.md` first. It combines SQLi and CSRF outcomes and explains which behaviours were counted as clean WAF blocks, non-clean redirects, server errors, or expected baseline vulnerability.
