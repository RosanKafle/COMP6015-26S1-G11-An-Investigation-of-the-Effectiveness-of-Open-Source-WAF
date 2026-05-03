# Week 6: Introduce WAF #2 (Coraza)

## What was tested

- Rechecked WAF #1 (ModSecurity) using sqlmap against the DVWA SQL Injection page
- Tested the same sqlmap pattern through WAF #2 (Coraza) at `http://localhost:8080`
- Ran Wapiti against the Coraza path and saved both text and HTML outputs
- Preserved the raw sqlmap and Wapiti outputs in this folder

## Evidence-backed observations

- Baseline reference: manual Week 3 testing confirmed DVWA was vulnerable to SQL injection and reflected XSS without a WAF
- Automated baseline reference: the saved Week 3 sqlmap runs were weaker because they redirected to `login.php` and did not preserve a clean authenticated session
- WAF #1 (ModSecurity): `sqlmap-waf1-week6.txt` ended with no injectable parameter detected and `500` returned 908 times
- WAF #2 (Coraza): `sqlmap-waf2.txt` ended with no injectable parameter detected and `403` returned 909 times
- `wapiti-waf2.txt` shows a limited crawl of one URL plus header and configuration findings. It does not by itself prove that every dynamic attack class was blocked.

## Interpretation

- Both WAF paths disrupted the tested sqlmap SQL injection run
- Coraza produced a cleaner explicit block response in the saved evidence, while ModSecurity produced repeated internal server errors
- No broader cross-WAF claim should be made from Week 6 beyond this saved sqlmap comparison and the limited Wapiti crawl

## Next steps

- Week 7: extend testing with obfuscated SQLi and XSS payloads and record which results are backed by raw exports
