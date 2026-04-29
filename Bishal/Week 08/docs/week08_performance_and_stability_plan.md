# Week 08 Performance and Stability Plan

## Focus

Measure basic WAF overhead and record environment stability observations.

## Performance Tools

The performance stage uses:

- ApacheBench (`ab`).
- hey.

## Test States

The comparison uses:

- No WAF / baseline.
- ModSecurity with OWASP CRS.
- Coraza with OWASP CRS.

## Metrics

Metrics recorded:

- Total requests.
- Concurrency.
- Failed requests.
- Requests per second.
- Mean time per request.
- Response code distribution.
- Stability observations during load.

## Week 08 Outputs

- Reproducibility runbook.
- Curl troubleshooting screenshots.
- Environment configuration notes.
- Performance test plan for Week 09 analysis.

