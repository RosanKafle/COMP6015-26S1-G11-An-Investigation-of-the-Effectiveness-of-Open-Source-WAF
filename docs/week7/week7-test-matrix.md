| Test ID | Tool | Attack Type | Variation Type | Target Page | Payload Summary | WAF | Result | Notes |
|--------|------|-------------|----------------|-------------|-----------------|-----|--------|-------|
| W7-01 | Burp | SQLi | URL encoding | DVWA SQL Injection | %27%20OR%20%271%27%3D%271 | ModSecurity | Blocked | 403 Forbidden |
| W7-02 | Burp | SQLi | Case/spacing variation | DVWA SQL Injection | '/**/OR/**/'1'='1 | ModSecurity | Blocked | 403 Forbidden |
| W7-03 | sqlmap | SQLi | Tamper script | DVWA SQL Injection | --tamper=space2comment | ModSecurity | Blocked | 403 repeated (149 times) |
| W7-04 | Burp | XSS | URL encoding | DVWA XSS Reflected | %3Cscript%3Ealert(1)%3C%2Fscript%3E | ModSecurity | Blocked | 400 Bad Request |
| W7-05 | Burp | XSS | Case variation | DVWA XSS Reflected | <ScRiPt>alert(1)</ScRiPt> | ModSecurity | Blocked | 403 Forbidden |
| W7-06 | Burp | SQLi | Request structure | DVWA SQL Injection | %27%20OR%20%271%27%3D%271&id2=test | ModSecurity | Blocked | 403 Forbidden |

Note:
`W7-06` is preserved only as a summary row in this matrix. The saved raw files in this folder directly support `W7-01` to `W7-05`, plus the sqlmap tamper run `W7-03`.
