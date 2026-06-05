# Week 07 DVWA Multi-Attack Testing

## Focus

Extend DVWA testing from SQL injection into multiple OWASP-style attack categories and basic evasion attempts.

## Tests Added

Cross-Site Scripting:

```html
<script>alert(1)</script>
```

Command Injection:

```text
; ls
```

Directory Traversal:

```text
../../../../etc/passwd
```

Automated scanning:

- SQLMap.
- Wapiti.
- Burp request modification.

## Evasion Testing

The Week 07 evidence includes:

- URL-encoded SQL injection payloads.
- Case and spacing variations.
- SQLMap tamper script testing.
- XSS encoding/case variation.
- Request structure changes.

## Week 07 Outputs

- DVWA multi-attack working copy.
- CRS tuning screenshot.
- ModSecurity log screenshot.
- Burp/evasion test matrix.
- SQLMap tamper output.

