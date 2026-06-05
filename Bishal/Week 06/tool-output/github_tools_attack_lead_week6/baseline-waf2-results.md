## Additional baseline tools against WAF #2
- Wapiti scan: wapiti-waf2.html
  - SQLi/XSS/Command Execution/Path Traversal: all 0 (blocked by Coraza).
  - Header issues (CSP, clickjacking, MIME): 3 findings (static config issues).
  - Compared to Week 3 baseline: dynamic vulns now blocked, headers unchanged.
