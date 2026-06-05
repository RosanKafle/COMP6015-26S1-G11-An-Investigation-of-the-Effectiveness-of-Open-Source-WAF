# Week 06 DVWA Environment and SQL Injection Tests

## Focus

Document the DVWA test environment and confirm SQL injection behaviour across WAF modes.

## Environment

The lab uses a controlled attacker/target setup:

- Attacker machine: Kali Linux.
- Target machine: Ubuntu Server running Apache, DVWA, and WAF protection.
- WAF #1: ModSecurity with OWASP CRS.

## Testing Modes

Detection mode:

```apache
SecRuleEngine DetectionOnly
```

Blocking mode:

```apache
SecRuleEngine On
```

## SQL Injection Tests

Manual SQL injection payload:

```text
' OR '1'='1
```

Observed progression:

- Detection mode: the request is logged and the application remains exploitable.
- Blocking mode: the request is blocked, returning a forbidden/error response.
- SQLMap: automated SQL injection is disrupted when WAF blocking is enabled.

## Week 06 Outputs

- DVWA test working copy.
- Manual SQL injection result notes.
- SQLMap output.
- WAF #1 versus WAF #2 comparison evidence.

