# WAF #1 behaviour with sqlmap (Week 6 check)

- Target: http://dvwa.local/vulnerabilities/sqli/?id=1&Submit=Submit
- Tool: sqlmap (--batch --risk=2 --level=2)
- Result: No injectable parameter detected.
- HTTP errors: ~900 responses with status 500 during the run.
- Baseline reference: manual Week 3 testing confirmed the DVWA page was vulnerable without a WAF, while the saved automated sqlmap baseline remained inconclusive because of login and session issues.
- Interpretation: with WAF #1 enabled, the saved sqlmap run could no longer identify an injectable parameter. Many payloads triggered internal errors, which is consistent with WAF disruption but also shows the response path was not cleanly tuned.
