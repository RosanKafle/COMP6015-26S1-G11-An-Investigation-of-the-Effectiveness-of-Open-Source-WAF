# Week 7 Completion

Advanced evasion testing was completed against the ModSecurity path using Burp Suite Repeater and sqlmap.

Evidence-backed saved results:

- `W7-01` URL-encoded SQLi: blocked with `403 Forbidden`
- `W7-02` case and spacing SQLi variation: blocked with `403 Forbidden`
- `W7-03` sqlmap `--tamper=space2comment`: blocked with `403 Forbidden` repeated 149 times
- `W7-04` URL-encoded reflected XSS: blocked with `400 Bad Request`
- `W7-05` mixed-case reflected XSS: blocked with `403 Forbidden`
- `W7-06` request-structure SQLi is recorded in the test matrix, but a dedicated raw request and response export was not preserved in `docs/week7/`

Outcome:
All saved Week 7 artifacts show blocked obfuscated SQLi and XSS attempts against ModSecurity. The current docs export does not preserve a successful bypass.
