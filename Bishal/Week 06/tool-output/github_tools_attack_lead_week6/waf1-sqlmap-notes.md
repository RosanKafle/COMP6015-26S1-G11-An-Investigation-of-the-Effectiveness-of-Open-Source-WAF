# WAF #1 behaviour with sqlmap (Week 6 check)

- Target: http://dvwa.local/vulnerabilities/sqli/?id=1&Submit=Submit
- Tool: sqlmap (--batch --risk=2 --level=2)
- Result: No injectable parameter detected.
- HTTP errors: ~900 responses with status 500 during the run.
- Interpretation: DVWA was exploitable in the baseline (Week 3),
  but with WAF #1 enabled and tuned, sqlmap can no longer exploit the SQLi.
  Many payloads now trigger internal errors, consistent with WAF disruption.
