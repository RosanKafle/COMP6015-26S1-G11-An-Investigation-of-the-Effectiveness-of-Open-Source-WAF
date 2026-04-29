# OWASP Top 10 Mapping Summary

The project maps DVWA and WAF testing to the OWASP Top 10 web application risk categories.

## Strongest Test Coverage

- Injection: SQL injection, command injection, and automated SQLMap testing.
- Security logging and alerting: ModSecurity logs recorded suspicious requests.
- Security misconfiguration: comparison between WAF monitoring and blocking behavior.

## Partial or Conceptual Coverage

- Broken access control: mostly application logic, not strongly mitigated by WAF.
- Cryptographic failures: HTTP versus HTTPS is a configuration issue outside WAF blocking.
- Insecure design: DVWA is intentionally insecure by design.
- Authentication failures: SQL injection login bypass style testing can show partial WAF support.

## Evidence Requirement

Each vulnerability category should ideally have:

- Payload or scan command.
- Screenshot of application behavior.
- HTTP status code.
- Matching WAF log excerpt.
- Result classification: allowed, detected only, blocked, or not applicable.

