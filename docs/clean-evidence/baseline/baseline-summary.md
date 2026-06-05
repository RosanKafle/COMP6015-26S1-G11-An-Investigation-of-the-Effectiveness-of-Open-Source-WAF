# Clean Baseline Evidence – No WAF

Scope:
- Application: DVWA only
- Condition: No WAF
- Purpose: Confirm which attacks succeed before WAF protection is applied

## Evidence collected

### 1. Manual SQL Injection
- Target: DVWA SQL Injection page
- Payload: `1 OR 1=1`
- Saved evidence: `manual-sqli-baseline.txt`
- Result: accepted by DVWA and returned user data for `admin`

---

### 2. Reflected XSS
- Target: DVWA XSS Reflected page
- Payload: `<script>alert(1)</script>`
- Saved evidence: `manual-xss-baseline.txt`
- Result: JavaScript alert executed in the browser

---

### 3. Authenticated sqlmap
- Target: DVWA SQL Injection endpoint
- Saved evidence:
  - `sqlmap-authenticated-baseline.txt`
  - `sqlmap-authenticated-baseline-test-output.txt`
- Result: the saved run did not confirm injection automatically
- Limitation: the raw output still shows a redirect to `login.php`, so this is not a clean authenticated automated baseline

---

## Baseline conclusion

The baseline is confirmed primarily by manual testing. The saved evidence shows that:

- manual SQL injection succeeded
- manual reflected XSS succeeded
- the exported sqlmap baseline attempt was inconclusive because the session state was not cleanly preserved

These results provide the comparison point for later ModSecurity and Coraza testing.
