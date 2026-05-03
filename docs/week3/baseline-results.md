# Week 3 DVWA Baseline Results

This file is retained as the Week 3 baseline note. For final reporting, use `../clean-evidence/baseline/` as the authoritative baseline summary.

## Manual findings

- SQL Injection page: payload `1 OR 1=1` returned user data, including `admin`
- XSS Reflected page: payload `<script>alert(1)</script>` executed in the browser

## Automated tool findings

- `sqlmap-baseline.txt` and `sqlmap-week3.txt` followed redirects to `login.php` and accepted server cookies with `security=impossible`
- `sqlmap-low.txt` failed to establish an SSL connection
- `sqlmap-fixed.txt` is another preserved attempt, but the exported output still does not provide a clean authenticated exploit result
- `wapiti-week3.txt` recorded header and configuration issues in a very limited crawl and did not report saved SQLi or XSS findings

## Week 3 conclusion

Week 3 successfully established manual baseline vulnerability on unprotected DVWA. The saved automated baseline outputs are useful lab records, but they are not strong enough to stand alone as proof of automated exploitation.
