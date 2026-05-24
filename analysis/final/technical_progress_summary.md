# Technical Progress Summary

This summary is generated only from structured raw files matching `output/*/*/*/run_*/detailed.csv`.
Setup/login rows are excluded from the metrics because they are not experiment traffic.

## Completed Experiments

- `baseline` / `none` / `attack_only` / `none`: 468 attack rows, 0 benign rows.
- `baseline` / `none` / `mixed` / `medium`: 665 attack rows, 5325 benign rows.
- `coraza` / `coraza` / `attack_only` / `none`: 463 attack rows, 0 benign rows.
- `coraza` / `coraza` / `mixed` / `medium`: 653 attack rows, 5220 benign rows.
- `modsec` / `modsecurity` / `attack_only` / `none`: 465 attack rows, 0 benign rows.
- `modsec` / `modsecurity` / `mixed` / `medium`: 661 attack rows, 5278 benign rows.

## Experiment Meaning

- `attack_only` with `load_level=none` means controlled attack requests were sent without concurrent benign live-traffic threads.
- `mixed` with `load_level=medium` means controlled attack requests were sent while benign DVWA browsing traffic was running concurrently.

## WAFs Present in Current Data

- `baseline` (`none`)
- `coraza` (`coraza`)
- `modsec` (`modsecurity`)

## Attack Classes Present in Current Data

- `authorization_bypass`
- `brute_force`
- `csrf`
- `javascript`
- `sqli`
- `weak_session_ids`
- `xss`

## Why Confusion Matrices Are Included

The confusion matrix reduces the HTTP outcomes into security decision counts: true positives, false negatives, false positives, and true negatives. Clean WAF blocks are only status codes `403`, `406`, and `501`. Server errors are not counted as clean blocks.

## Why Missed Attacks Are Listed Individually

`missed_attacks.csv` lists every attack row that was not cleanly blocked. This makes it possible to inspect the exact URL, request name, payload, response code, and reason category for each allowed, redirected, errored, timed-out, or unknown attack request.

## Report Writer Evidence Files

- `analysis/final/confusion_matrices.csv`
- `analysis/final/missed_attacks.csv`
- `analysis/final/attack_class_breakdown.csv`
- `analysis/final/benign_live_traffic_breakdown.csv`
- Raw source files under `output/*/*/*/run_*/detailed.csv`
- Run metadata and validation files under each `run_*` folder

## Missing Data

- NAXSI is missing from the current structured detailed CSV data.
- Path traversal attack rows are not present in the current structured detailed CSV data.
- ZAP alert-derived attack classification is not available in the current raw files because all `zap_alert_count` values are zero and older detailed CSVs do not contain `detected_attack_type` fields.

## Important Counting Rules Used

- Server errors (`500+`) are counted as `server_error`, not as clean blocks.
- Redirects are counted as `redirected`, not as successful attacks.
- Benign redirects are treated as true negatives for the confusion matrix because DVWA login/session flows can legitimately redirect.
- NAXSI is not included because no NAXSI `detailed.csv` files exist in the structured output data.
