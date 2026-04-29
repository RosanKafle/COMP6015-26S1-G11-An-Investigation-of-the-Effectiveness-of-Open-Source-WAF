# Week 03 Baseline Testing and OWASP Scope

## Focus

Build baseline results before WAF blocking and connect the test plan to OWASP Top 10 categories.

## Baseline Testing Direction

The Week 03 baseline stage checks which attacks work before strong WAF blocking is applied. The main baseline tools and methods are:

- Manual SQL injection.
- SQLMap SQL injection testing.
- Wapiti scanning.
- Burp request interception and replay practice.
- ZAP and Nikto exploration.

## OWASP Top 10 Scope

The OWASP Top 10 document was used to decide which risks were practical to test in DVWA:

- A01 Broken Access Control: reviewed conceptually through direct access and application flow.
- A02 Security Misconfiguration: compared exposed application behaviour with WAF-protected behaviour.
- A04 Cryptographic Failures: noted through HTTP/plaintext lab setup.
- A05 Injection: tested directly through SQL injection and command injection.
- A07 Authentication Failures: considered through login bypass-style input testing.
- A09 Security Logging and Monitoring Failures: evaluated through ModSecurity/Apache log output.

## Week 03 Outputs

- Baseline testing notes.
- SQLMap and Wapiti outputs from shared group evidence.
- Initial OWASP Top 10 research document.
- Spreadsheet/result tracking material.

