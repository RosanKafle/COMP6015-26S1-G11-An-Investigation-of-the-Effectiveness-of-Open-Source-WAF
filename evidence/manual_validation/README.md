# Manual Validation Evidence

This folder contains manually selected SQL injection and CSRF validation evidence used to support the empirical WAF evaluation.

The manual tests were designed to supplement the automated attack-only and mixed-traffic experiments. Payloads were selected and grouped by attack pattern so that blocked, allowed, redirected, and server-error outcomes could be interpreted clearly.

## Contents

- `payloads/` contains the curated manual payload/test definitions.
- `results/` contains raw manual result CSVs and derived summary tables.
- `ATTACK_TAXONOMY_AND_TEST_DESIGN.md` explains the tested attack classes, payload patterns, and interpretation model.

## Key result files

- `results/manual_classification_summary.md`
- `results/manual_what_was_blocked.csv`
- `results/manual_what_was_not_cleanly_blocked.csv`
- `results/manual_sqli_expanded_overall_summary.csv`
- `results/manual_sqli_expanded_not_cleanly_blocked.csv`
- `results/manual_csrf_overall_summary.csv`

## Interpretation rule

Only HTTP 403, 406, and 501 were counted as clean WAF blocks. Redirects and HTTP 500 responses were recorded separately and were not counted as clean WAF detections.
