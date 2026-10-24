# Classification rules

| Expected traffic | Verified WAF action | Classification |
|---|---|---|
| MALICIOUS | BLOCKED | TP |
| MALICIOUS | ALLOWED | FN |
| NORMAL | BLOCKED | FP |
| NORMAL | ALLOWED | TN |
| Either | UNKNOWN | UNKNOWN |

HTTP 403/406 alone is not evidence that a WAF blocked the request. A 200 response
may be a login page, a soft block, or an application error. Redirects, timeouts and
unattributed errors remain UNKNOWN. A matched rule in detection-only mode is not
a blocking decision. Absence of a WAF log is not proof of allowance.

Use a correlation ID shared by the request, WAF audit record and/or backend access
record. BLOCKED requires an attributable WAF intervention. ALLOWED requires evidence
that this request passed the WAF to the intended application, with application/session
prerequisites checked. Record an evidence reference and review reason.

These labels measure WAF disposition, not successful exploitation. Invalid payloads,
unsupported endpoints and expired sessions must be excluded from attack-validity
claims. UNKNOWN rows stay visible and are excluded from the four rate denominators.
