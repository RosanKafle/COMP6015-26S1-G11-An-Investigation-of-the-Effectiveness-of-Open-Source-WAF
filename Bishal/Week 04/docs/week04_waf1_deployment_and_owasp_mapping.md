# Week 04 WAF #1 Deployment and OWASP Mapping

## Focus

Deploy the first WAF and repeat baseline attacks with ModSecurity/OWASP CRS active.

## WAF #1 Architecture

The intended architecture is:

`Client / Kali Linux -> Apache Web Server with ModSecurity -> DVWA`

ModSecurity inspects incoming HTTP requests before they reach DVWA. OWASP CRS supplies the rule set used for detecting common attack patterns.

## OWASP Mapping Work

The OWASP Top 10 document was expanded to connect DVWA tests to risk categories:

- Injection: SQL injection and command injection.
- Security Misconfiguration: WAF disabled/detection-only versus blocking behaviour.
- Logging and Monitoring: Apache/ModSecurity error logs.
- Broken Access Control and Insecure Design: noted as application-level issues.

## Week 04 Outputs

- OWASP Top 10 test mapping document.
- ModSecurity detection-mode status note.
- WAF #1 initial test comparison direction.

