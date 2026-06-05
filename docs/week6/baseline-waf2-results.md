## Additional baseline tools against WAF #2

- Saved sources:
  - `wapiti-waf2.txt`
  - `wapiti-waf2.html`

- What the saved Wapiti output supports:
  - the scan completed against the Coraza path
  - one URL/form path was discovered in the saved crawl
  - header and configuration issues were still visible, including missing `CSP`, `X-Frame-Options`, and `X-Content-Type-Options`
  - no SQLi or XSS findings were reported in this limited saved crawl

- What the saved Wapiti output does not support:
  - it does not prove that SQLi, XSS, command execution, and path traversal were all comprehensively blocked by Coraza
  - it should not be used as a full dynamic vulnerability comparison with the Week 3 baseline
