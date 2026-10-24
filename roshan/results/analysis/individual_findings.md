# Individual WAF Results Analysis

This analysis uses the existing project result datasets as read-only sources. The results were independently validated before analysis.

## Validation Status

- Independent validation completed with 66 checks passed and 0 checks failed.
- Original project evidence was not modified.
- Setup traffic was excluded from normal false-positive analysis.

## Overall Detection Performance

- baseline (attack_only): detection 0.0%, false positives 0.0%, server errors 4.487%, average response time 6.196 ms.
- baseline (mixed): detection 0.0%, false positives 0.0%, server errors 0.484%, average response time 6.22 ms.
- coraza (attack_only): detection 34.773%, false positives 0.0%, server errors 4.536%, average response time 9.022 ms.
- coraza (mixed): detection 35.069%, false positives 0.0%, server errors 0.494%, average response time 16.686 ms.
- modsec (attack_only): detection 34.839%, false positives 0.0%, server errors 4.516%, average response time 7.946 ms.
- modsec (mixed): detection 34.947%, false positives 0.0%, server errors 0.522%, average response time 9.925 ms.

## Attack-Specific Detection Gaps

### coraza

- authorization_bypass: 0 blocked, 40 allowed and 0 server errors from 40 requests. Detection rate: 0%.
- brute_force: 40 blocked, 60 allowed and 0 server errors from 100 requests. Detection rate: 40%.
- csrf: 0 blocked, 40 allowed and 0 server errors from 40 requests. Detection rate: 0%.
- javascript: 20 blocked, 40 allowed and 0 server errors from 60 requests. Detection rate: 33.333%.
- sqli: 41 blocked, 21 allowed and 21 server errors from 83 requests. Detection rate: 49.398%.
- weak_session_ids: 0 blocked, 60 allowed and 0 server errors from 60 requests. Detection rate: 0%.
- xss: 60 blocked, 20 allowed and 0 server errors from 80 requests. Detection rate: 75%.
### modsec

- authorization_bypass: 0 blocked, 40 allowed and 0 server errors from 40 requests. Detection rate: 0%.
- brute_force: 40 blocked, 60 allowed and 0 server errors from 100 requests. Detection rate: 40%.
- csrf: 0 blocked, 40 allowed and 0 server errors from 40 requests. Detection rate: 0%.
- javascript: 20 blocked, 40 allowed and 0 server errors from 60 requests. Detection rate: 33.333%.
- sqli: 42 blocked, 21 allowed and 21 server errors from 84 requests. Detection rate: 50%.
- weak_session_ids: 0 blocked, 60 allowed and 0 server errors from 60 requests. Detection rate: 0%.
- xss: 60 blocked, 21 allowed and 0 server errors from 81 requests. Detection rate: 74.074%.

## False-Positive Findings

The validated mixed-traffic results report a 0% false-positive rate for baseline, Coraza and ModSecurity.

## Comparative Interpretation

Coraza and ModSecurity show broadly comparable detection performance in the validated dataset.
For attack-only testing, ModSecurity reports a slightly higher overall detection rate than Coraza.
For mixed testing, Coraza reports a slightly higher overall detection rate than ModSecurity.
The differences are small, so the results do not support claiming that one WAF is universally superior based on detection rate alone.

## Missed and Non-Cleanly-Blocked Attacks

The analysis treats allowed attacks and server errors separately from clean WAF blocks. Server errors are not counted as successful WAF detections.
SQL injection represents an important detection gap because both Coraza and ModSecurity produced allowed requests as well as server-error responses.
XSS also produced allowed requests for both WAFs, while several other attack categories in the tested dataset were not cleanly blocked.

## Reproducibility

The analysis reads the project datasets directly from the Git repository and produces separate files under roshan/results/analysis/.
The original group result files remain unchanged.
