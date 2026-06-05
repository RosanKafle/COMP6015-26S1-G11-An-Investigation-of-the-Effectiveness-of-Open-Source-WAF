# Week 6 WAF Comparison Analysis

## Purpose
Week 6 introduced WAF #2, Coraza with OWASP CRS, in front of DVWA. The purpose of this week was to compare the initial behaviour of WAF #2 against WAF #1 using the same SQL Injection and automated scanning approach.

## Files reviewed
- baseline-waf2-results.md
- sqlmap-waf1-week6.txt
- sqlmap-waf2.txt
- status.md
- waf1-sqlmap-notes.md
- wapiti-waf2.txt

## Week 6 Comparison Table

| Test | WAF #1: ModSecurity CRS | WAF #2: Coraza CRS | Interpretation |
|------------------|---|---|---|
| sqlmap SQLi test | No injectable parameter detected; many HTTP 500 responses | No injectable parameter detected; many HTTP 403 responses | Both WAFs disrupted sqlmap SQLi testing, but they responded differently |
| Wapiti scan | Not available in uploaded Week 6 files | SQLi, XSS, Command Execution and Path Traversal all reported as 0 | Coraza appeared effective against Wapiti dynamic attack modules |
| Header/configuration issues | Not confirmed in Week 6 files | CSP, X-Frame-Options, X-Content-Type-Options and HTTP issues remained | WAF blocked dynamic attacks but did not fix application/header configuration issues |
| Tuning status | WAF #1 already checked/tuned | WAF #2 not tuned yet | Week 6 should be treated as first-pass WAF #2 behaviour |

## Role 4 Interpretation

The Week 6 results show that both WAF #1 and WAF #2 prevented sqlmap from confirming SQL Injection through the tested DVWA parameter. WAF #1 produced many HTTP 500 responses, while WAF #2 produced many HTTP 403 responses. This suggests that both WAFs disrupted the automated attack, but Coraza showed a clearer blocking-style response through repeated Forbidden responses.

The Wapiti result for WAF #2 is also important because SQL Injection, XSS, Command Execution and Path Traversal findings were reported as 0. However, Wapiti still identified missing security headers and HTTP-related configuration issues. This means the WAF may reduce dynamic exploitability, but it does not automatically correct insecure application or server configuration.

Overall, Week 6 provides useful comparison evidence. WAF #2 should be recorded as initially effective against the tested automated dynamic attacks, while remaining header findings should be classified as unresolved configuration weaknesses.

## Week 6 Limitations

- WAF #2 was tested in first-pass/default behaviour only, without tuning.
- sqlmap did not confirm SQL Injection, but this should be described as attack disruption rather than absolute proof that all SQL Injection was impossible.
- Wapiti crawled a limited scope, so results should be treated as supporting evidence, not complete coverage.
- Header findings remained because WAF protection does not automatically fix missing application security headers.
