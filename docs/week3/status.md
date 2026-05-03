# Week 3: Baseline Testing on Unprotected DVWA

Focus:
Establish baseline application behaviour before WAF enforcement.

Completed work:
- Tested DVWA SQL injection manually at low security
- Tested DVWA reflected XSS manually at low security
- Ran multiple sqlmap attempts and saved the raw outputs
- Ran Wapiti and saved both text and HTML outputs

Evidence-backed observations:
- Manual SQL injection succeeded on the DVWA SQL Injection page
- Manual reflected XSS executed on the DVWA XSS Reflected page
- Saved sqlmap runs were not a clean authenticated baseline because they redirected to `login.php`, reused server-set cookies, or failed to establish the intended session state
- Saved Wapiti output recorded header and configuration issues, but not saved dynamic SQLi or XSS findings in the limited crawl

Outcome:
Week 3 establishes manual baseline vulnerability. For final analysis, use `../clean-evidence/baseline/` as the authoritative baseline summary.
