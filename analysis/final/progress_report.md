# Technical Progress Report

Project title: **An Investigation of the Effectiveness of Open-Source Web Application Firewalls**

Data source: structured experiment outputs in `output/`

Report date: 2026-05-20

## 1. Short Summary

The latest structured data contains results for:

- Baseline, meaning DVWA with no WAF.
- ModSecurity.
- Coraza.

Each environment has:

- One `attack_only` run with no background load.
- One `mixed` run with medium benign traffic running at the same time as attacks.

NAXSI results are not present in the current `output/` dataset.

Main finding:

- Baseline blocked **0%** of attack requests.
- ModSecurity blocked about **34.9%** of attack requests.
- Coraza blocked about **34.9%** of attack requests.
- No benign mixed-traffic requests were blocked by either WAF.
- Coraza had higher latency overhead than ModSecurity, especially during mixed traffic.

Important interpretation:

These are useful progress results, but they are not yet enough for final statistical conclusions because there is only one run per condition and NAXSI data is missing.

## 2. Experiment Setup

The framework correctly separates ZAP from DVWA.

| Component | Endpoint | Role |
| --- | --- | --- |
| ZAP API | `http://127.0.0.1:8080` | Controls ZAP scanning/proxy features |
| ZAP proxy | `http://127.0.0.1:8080` | Captures/proxies traffic when enabled |
| Baseline DVWA | `http://192.168.209.130/DVWA` | DVWA with ModSecurity disabled |
| ModSecurity DVWA | `http://192.168.209.130/DVWA` | Same DVWA host with ModSecurity enabled |
| Coraza DVWA | `http://192.168.209.130:8080/DVWA` | DVWA through Coraza reverse proxy |

All completed runs used:

- DVWA security level: `low`
- ZAP proxy: enabled
- WAF state confirmation: manual confirmation
- Remote SSH WAF state check: not used

Because baseline and ModSecurity use the same DVWA URL, the difference between those two runs depends on the Apache ModSecurity module being disabled or enabled before the run.

## 3. Data Used

Setup/login rows were excluded from the main results below. Only `attack_only` and `mixed` experiment rows are counted.

| Environment | WAF | Phase | Load | Run ID | Attack Rows | Benign Rows | Total Rows | Validation |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | --- |
| baseline | none | attack_only | none | `20260519_063833` | 468 | 0 | 468 | PASS |
| baseline | none | mixed | medium | `20260519_074733` | 665 | 5,325 | 5,990 | PASS |
| modsec | modsecurity | attack_only | none | `20260519_064610` | 465 | 0 | 465 | PASS |
| modsec | modsecurity | mixed | medium | `20260519_073041` | 661 | 5,278 | 5,939 | PASS |
| coraza | coraza | attack_only | none | `20260519_074907` | 463 | 0 | 463 | PASS |
| coraza | coraza | mixed | medium | `20260519_064803` | 653 | 5,220 | 5,873 | PASS |

Overall main experiment data:

| Data Type | Count |
| --- | ---: |
| Completed structured runs | 6 |
| Total main experiment rows | 19,198 |
| Controlled attack rows | 3,375 |
| Benign mixed-traffic rows | 15,823 |

## 4. How the Metrics Were Calculated

The current framework uses HTTP response behavior to classify outcomes.

| Outcome | Definition |
| --- | --- |
| Blocked | HTTP `403`, `406`, or `501` |
| Allowed | HTTP `200` to `299` |
| Redirect | HTTP `301`, `302`, `303`, `307`, or `308` |
| Server error | HTTP `500` or above |

Detection rate:

```text
blocked attack requests / total attack requests * 100
```

False positive rate:

```text
blocked benign requests / total benign requests * 100
```

Server errors are **not** counted as successful WAF blocks. This is important because a `500` or `502` response may show application instability, proxy failure, or backend failure rather than correct WAF detection.

## 5. Main Results

| Environment | Phase | Attack Detection | False Positive Rate | Avg Response Time | Attack Server Errors |
| --- | --- | ---: | ---: | ---: | ---: |
| baseline | attack_only | 0.000% | 0.000% | 6.196 ms | 21 |
| baseline | mixed medium | 0.000% | 0.000% | 6.220 ms | 29 |
| ModSecurity | attack_only | 34.839% | 0.000% | 7.946 ms | 21 |
| ModSecurity | mixed medium | 34.947% | 0.000% | 9.925 ms | 31 |
| Coraza | attack_only | 34.773% | 0.000% | 9.022 ms | 21 |
| Coraza | mixed medium | 35.069% | 0.000% | 16.686 ms | 29 |

What this means:

- Baseline behaved as expected: no attack requests were blocked.
- ModSecurity and Coraza gave almost identical overall detection rates.
- Mixed traffic did not reduce detection in the current medium-load runs.
- No benign requests were blocked, so no false positives were observed in the current mixed dataset.
- Coraza showed higher response-time overhead than ModSecurity.

## 6. Combined Attack Results

This table combines attack-only and mixed-medium attack rows.

| Environment | Attack Requests | Blocked | Allowed | Server Errors | Detection Rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 1,133 | 0 | 1,083 | 50 | 0.000% |
| ModSecurity | 1,126 | 393 | 681 | 52 | 34.902% |
| Coraza | 1,116 | 390 | 676 | 50 | 34.946% |

Technical feedback:

- Both WAFs blocked about one third of controlled attack requests.
- Around 60% of attack requests still received HTTP `200` through both WAFs.
- The difference between ModSecurity and Coraza is extremely small in this dataset, so it should not be described as one WAF being clearly better than the other for detection.

## 7. Detection by Attack Type

This is the most useful table for the research report because WAF effectiveness depends strongly on attack type.

| Attack Type | ModSecurity Blocked/Sent | ModSecurity Rate | Coraza Blocked/Sent | Coraza Rate | Interpretation |
| --- | ---: | ---: | ---: | ---: | --- |
| SQL injection | 100 / 200 | 50.00% | 99 / 199 | 49.75% | Both WAFs blocked about half of SQLi requests. |
| XSS | 147 / 197 | 74.62% | 147 / 196 | 75.00% | Strongest category for both WAFs. |
| Brute force | 98 / 245 | 40.00% | 96 / 241 | 39.83% | Partial blocking only. |
| CSRF | 0 / 98 | 0.00% | 0 / 96 | 0.00% | Not blocked by either WAF in this test. |
| JavaScript tampering | 48 / 146 | 32.88% | 48 / 144 | 33.33% | Some blocking, but most requests allowed. |
| Weak session IDs | 0 / 144 | 0.00% | 0 / 144 | 0.00% | Not blocked; this is more application weakness/reconnaissance than a signature payload. |
| Authorization bypass | 0 / 96 | 0.00% | 0 / 96 | 0.00% | Not blocked; likely needs application-level controls or custom WAF rules. |

Baseline detection was 0% for every attack type.

Research interpretation:

- XSS and SQL injection are the strongest categories for both WAFs.
- Brute force and JavaScript tampering are only partly covered.
- CSRF, weak session IDs, and authorization bypass are not handled by the current WAF configurations.
- Overall detection rate alone is not enough. The final thesis should discuss each attack class separately.

## 8. Mixed-Traffic Results

Mixed mode is important because it tests WAF behavior while normal users and attacks happen at the same time.

| Environment | Attack Rows | Blocked Attacks | Detection Rate | Benign Rows | Blocked Benign | False Positive Rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | 665 | 0 | 0.000% | 5,325 | 0 | 0.000% |
| ModSecurity | 661 | 231 | 34.947% | 5,278 | 0 | 0.000% |
| Coraza | 653 | 229 | 35.069% | 5,220 | 0 | 0.000% |

Detection change from attack-only to mixed medium:

| WAF | Attack-Only Detection | Mixed-Medium Detection | Change |
| --- | ---: | ---: | ---: |
| ModSecurity | 34.839% | 34.947% | +0.108 percentage points |
| Coraza | 34.773% | 35.069% | +0.296 percentage points |

This does **not** prove that mixed traffic improves detection. The change is very small and there is only one run per condition. The safer conclusion is that medium mixed traffic did not noticeably reduce detection in the current dataset.

## 9. False Positive Results

False positives mean benign requests being blocked.

| Environment | Benign Requests | Benign Allowed | Benign Blocked | False Positive Rate | Avg Benign Latency |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 5,325 | 5,325 | 0 | 0.000% | 6.339 ms |
| ModSecurity | 5,278 | 5,278 | 0 | 0.000% | 10.315 ms |
| Coraza | 5,220 | 5,220 | 0 | 0.000% | 17.510 ms |

Technical feedback:

- This is a good early result because neither WAF disrupted the benign traffic generated by the framework.
- However, the result only applies to the current benign traffic model.
- Dedicated `benign_only` runs are still needed before making a strong final false-positive claim.

## 10. Performance Results

| Condition | Baseline Avg | ModSecurity Avg | ModSecurity Overhead | Coraza Avg | Coraza Overhead |
| --- | ---: | ---: | ---: | ---: | ---: |
| attack_only, no load | 6.196 ms | 7.946 ms | +1.750 ms | 9.022 ms | +2.826 ms |
| mixed, medium load | 6.220 ms | 9.925 ms | +3.705 ms | 16.686 ms | +10.466 ms |

Technical feedback:

- ModSecurity added latency but stayed closer to baseline.
- Coraza added much higher latency during mixed medium traffic.
- Since ModSecurity and Coraza had similar detection rates, latency becomes an important comparison point.

## 11. Server Errors

Server errors were kept separate from WAF blocks.

| Environment | Phase | HTTP 200 | HTTP 403 | HTTP 500 | HTTP 502 |
| --- | --- | ---: | ---: | ---: | ---: |
| baseline | attack_only | 447 | 0 | 21 | 0 |
| baseline | mixed | 636 | 0 | 29 | 0 |
| ModSecurity | attack_only | 282 | 162 | 21 | 0 |
| ModSecurity | mixed | 399 | 231 | 29 | 2 |
| Coraza | attack_only | 281 | 161 | 21 | 0 |
| Coraza | mixed | 395 | 229 | 29 | 0 |

Technical feedback:

- HTTP `403` responses are counted as WAF blocks.
- HTTP `500` and `502` responses are counted as server errors.
- The baseline also has 500 errors, so some errors are likely caused by DVWA/backend behavior rather than WAF blocking.
- The two ModSecurity `502` responses should be checked in server/proxy logs if available.

## 12. Data Quality Feedback

Strong points:

- The output structure is clean and reproducible.
- Each run has raw data, summary data, metadata, and validation output.
- Attack and benign traffic are clearly labelled.
- The dataset separates baseline, ModSecurity, and Coraza conditions.
- The framework does not hide server errors.

Issues to fix before the final dissertation:

| Issue | Why It Matters | Recommended Fix |
| --- | --- | --- |
| NAXSI data missing | The project title compares open-source WAFs, and NAXSI is part of the planned comparison. | Run NAXSI attack-only and mixed-medium experiments. |
| No benign-only runs | False positives are currently based only on mixed traffic. | Run `benign_only` for each environment. |
| One run per condition | Results are descriptive, not statistically strong. | Repeat each condition at least three times. |
| No low/high mixed-load data | Load sensitivity cannot be fully assessed. | Run mixed low and mixed high conditions. |
| Remote WAF state not checked | Baseline and ModSecurity share the same URL, so setup mistakes are possible. | Use `--check-remote-state` where possible. |
| ZAP alert counts are all zero | Current findings are based on HTTP blocking, not ZAP alert correlation. | Enable and validate ZAP alert lookup if needed. |
| ModSecurity mixed folder name differs from internal run ID | Provenance could confuse readers. | Document it or rename/archive consistently. |
| One validation file references an old flat CSV path | Minor documentation inconsistency. | Regenerate validation for that run if possible. |

## 13. Suggested Thesis Wording

The current data supports this kind of careful statement:

> In the current controlled DVWA experiments, both ModSecurity and Coraza improved HTTP-level blocking compared with the no-WAF baseline. Their overall blocking rates were similar, at approximately 35% of controlled attack requests. Detection was strongest for XSS and SQL injection payloads, while CSRF, weak session ID, and authorization-bypass requests were not blocked by the tested configurations. No benign mixed-traffic requests were blocked, but further benign-only and repeated runs are required before making a final claim about false-positive behavior. Coraza showed higher latency overhead than ModSecurity under mixed medium load.

Avoid saying:

- One WAF is definitively better overall.
- The result is statistically significant.
- CSRF or authorization bypass protection is complete.
- Server errors are successful WAF blocks.
- NAXSI has been evaluated, unless its results are added later.

## 14. Recommended Next Steps

Priority order:

1. Run NAXSI attack-only and mixed-medium experiments.
2. Run benign-only experiments for baseline, ModSecurity, Coraza, and NAXSI.
3. Repeat each condition at least three times.
4. Add mixed low-load and high-load experiments.
5. Collect WAF logs and server logs for blocked and server-error requests.
6. Decide whether ZAP alert correlation is required, then rerun with alert lookup enabled if needed.

## 15. Files Used

Raw data:

- `output/baseline/attack_only/none/run_20260519_063833/detailed.csv`
- `output/baseline/mixed/medium/run_20260519_074733/detailed.csv`
- `output/modsec/attack_only/none/run_20260519_064610/detailed.csv`
- `output/modsec/mixed/medium/run_20260519_033300_rerun/detailed.csv`
- `output/coraza/attack_only/none/run_20260519_074907/detailed.csv`
- `output/coraza/mixed/medium/run_20260519_064803/detailed.csv`

Generated summary files:

- `analysis/final/final_summary.csv`
- `analysis/final/final_attack_type_summary.csv`
- `analysis/final/final_benign_summary.csv`
- `analysis/final/final_waf_comparison.csv`
- `analysis/final/final_repetition_summary.csv`
- `analysis/final/report_summary.md`

Analysis command:

```bash
python3 analysis/metrics_analysis.py output/ --out analysis/final/final_summary.csv
```
