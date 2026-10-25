# Project Defense Guide

## One-Minute Summary

This project evaluates how effectively open-source web application firewalls
detect malicious HTTP requests in a controlled DVWA laboratory. The work compares
ModSecurity with OWASP CRS, Coraza and NAXSI using repeatable traffic generation,
baseline checks, WAF-protected runs, evidence correlation and confusion-matrix
analysis. The central finding is not that one WAF is universally best: effectiveness
depends on the attack class, payload transformation, ruleset and configuration.

## Claims We Can Defend

### Earlier automated ModSecurity and Coraza experiment

- Overall attack detection was 34.90% for ModSecurity and 34.95% for Coraza.
- Both recorded a 0.00% benign false-positive rate in the available mixed/setup data.
- SQL injection and XSS were detected more often than logic-level weaknesses such
  as CSRF, weak session IDs and authorization bypass.
- Coraza had greater latency overhead than ModSecurity in the available matched
  phases.

Primary source: `analysis/final/report_summary.md` and its linked CSV files.

### Reviewed matched ModSecurity and NAXSI experiment

- Each WAF received 1,684 reviewed requests: 1,564 malicious and 120 benign.
- ModSecurity recorded 1,564 true positives, 0 false negatives and 11 false
  positives in this dataset.
- NAXSI recorded 1,310 true positives, 254 false negatives and 12 false positives.
- Of NAXSI's 254 misses, 212 were double-encoded SQL injection or XSS requests and
  42 were baseline path-traversal requests.

Primary source: `Bishal/Final_Evidence/README.md` and the preserved evidence package.

### Controlled R11/R12 follow-up

- R11 included baseline-effect gates, 21 eligible attack cases, four benign controls,
  three WAFs and three repetitions.
- ModSecurity and Coraza blocked all 63 eligible attack observations; NAXSI blocked
  60 and allowed three repetitions of one newline command-separator case.
- R12 independently reproduced the NAXSI newline-separator gap for two variants,
  while semicolon, logical-AND and pipe variants were blocked in the tested setup.
- Expanded benign testing showed a sensitivity trade-off: NAXSI blocked 12/12
  deliberately attack-like benign observations, while ModSecurity and Coraza
  allowed them.

Primary source: `Pabin_WAF_Analysis/INTEGRATED_WAF_EVIDENCE_ANALYSIS.md` and
`r11_r12_waf_evaluation/`.

## Methodology to Explain

1. Establish an unprotected baseline and verify that the intended application
   effect is possible.
2. Send the eligible request through each WAF under a documented configuration.
3. Repeat requests to check consistency.
4. Correlate HTTP responses with WAF logs, backend evidence and application effects.
5. Classify true/false positives and negatives only when the evidence supports it.
6. Preserve raw evidence, metadata, hashes and analysis outputs for review.

The baseline-effect gate matters because a payload that fails against the
unprotected application cannot demonstrate successful WAF prevention.

## Important Limitations

- Results apply to the tested DVWA environment, payload corpus, versions and rules.
- A WAF allowing a malicious-labelled request does not automatically prove backend
  exploitation; application effects require separate confirmation.
- HTTP status alone is not a reliable detection label.
- The experiments used different corpora and methods, so their percentages must not
  be merged into one overall ranking.
- Unit tests validate software behaviour, not live WAF effectiveness.
- The selected benign samples are too small and deliberately shaped to estimate a
  population-wide false-positive rate.

## Likely Examiner Questions

**Why use a baseline?**  It verifies that an attack can produce its intended effect
without a WAF and prevents ineffective test cases from inflating detection results.

**Why is HTTP 403 insufficient?**  Reverse proxies, authentication redirects and
application errors can produce misleading status codes. The project correlates
responses with WAF and backend evidence.

**Why did NAXSI miss double-encoded or newline payloads?**  The tested NAXSI
configuration had narrower coverage for those representations. This is a
configuration-specific finding, not a universal statement about NAXSI.

**Why were ModSecurity and Coraza weak on CSRF or authorization bypass?**  WAFs
primarily inspect request patterns. Logic flaws often require application state and
authorization context that generic signatures do not possess.

**Can the WAF percentages be compared directly?**  Only within a matched experiment.
Cross-experiment percentages use different corpora, controls and validation rules.

**What is the practical recommendation?**  Use a WAF as one defensive layer, tune it
against representative benign and malicious traffic, monitor false positives, and
retain application-level controls for authentication, authorization and CSRF.

## Demonstration Path

1. Open `analysis/final/report_summary.md` for the earlier automated comparison.
2. Open `Bishal/Final_Evidence/README.md` for the matched ModSecurity/NAXSI matrix.
3. Open `Pabin_WAF_Analysis/INTEGRATED_WAF_EVIDENCE_ANALYSIS.md` for independent
   calculations, R11/R12 interpretation and limitations.
4. Show `framework/`, `tools/controlled_validation/` and
   `r11_r12_waf_evaluation/` to explain reproducibility.
5. Finish with the raw CSV, metadata or log supporting the specific claim being
   discussed.

## Before Presenting

- Use environment variables or interactive prompts for credentials.
- Confirm which experiment each slide references.
- Put the corpus size and denominator beside every percentage.
- Label generated test cases separately from completed live observations.
- Avoid universal claims such as "100% secure" or "best WAF."
