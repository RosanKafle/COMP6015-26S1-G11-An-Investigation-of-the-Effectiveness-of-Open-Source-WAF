# Week 4 controlled environment validation

## Purpose

This evidence establishes a reproducible and auditable experimental
environment before the full WAF effectiveness experiments begin.

## Validated topology

| Environment | Port | Protection | Backend |
|---|---:|---|---|
| Baseline | 8081 | ModSecurity disabled | DVWA |
| ModSecurity | 80 | ModSecurity 2.9.12 and CRS 4.25.0 | Same DVWA files |
| Coraza | 8080 | Coraza and CRS 4.25.0 | Baseline port 8081 |
| NAXSI | 8084 | NAXSI Core Rules | Baseline port 8081 |

The Kali client used `192.168.187.130`. The WAF server used
`192.168.187.134` during the final validation.

## Validation gates

1. Repository identity and four framework targets were verified.
2. WAF versions, rulesets, thresholds and configuration hashes were frozen.
3. All services and listening ports were validated.
4. The baseline was proven to use `SecRuleEngine Off`.
5. Three benign requests were sent through each environment.
6. All 12 benign responses returned HTTP 200 and produced identical
   normalized application-body fingerprints.
7. A fixed non-dataset XSS probe was repeated three times through every path.
8. The baseline allowed 3/3 probes and the three WAFs blocked 9/9 probes.
9. WAF results were correlated with audit or detection logs and rule IDs.
10. Source evidence was protected with SHA-256 manifests.

## Interpretation boundary

The XSS pilot is an operational calibration. It proves that blocking,
logging and evidence correlation function correctly. It is not treated as
the final effectiveness experiment because the probe used an unused
parameter on the login page.

The displayed request timings are connectivity diagnostics, not performance
benchmark results. Formal performance testing requires warm-up requests,
randomised execution order and substantially more repetitions.

## Primary analytical evidence

- `kali/06_benign_equivalence/benign_results.csv`
- `kali/07_xss_control_pilot/xss_control_results.csv`
- `ubuntu/08_log_correlation/combined_rule_correlation.csv`
- `ubuntu/08_log_correlation/correlation_summary.txt`
