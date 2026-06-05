# Week 7 Bypass and Evasion Analysis

## Purpose
Week 7 focused on testing whether the WAF could be bypassed using common evasion techniques. The goal was to evaluate how well the WAF handled modified attack payloads that attempt to avoid detection.

## Files reviewed
- week7-test-matrix.md
- W7-03-sqlmap-tamper-space2comment.txt
- status.md
- Burp Suite test outputs

## Evasion Test Results

| Test ID | Attack Type | Evasion Method | Result | Classification |
|-----------------------|---|---|---|---|
| W7-01 | SQL Injection | URL encoding | 403 Forbidden | Blocked |
| W7-02 | SQL Injection | Case/spacing variation | 403 Forbidden | Blocked |
| W7-03 | SQL Injection | sqlmap tamper (space2comment) | 403 repeated responses | Blocked |
| W7-04 | XSS | URL encoding | 400 Bad Request | Blocked |
| W7-05 | XSS | Case variation | 403 Forbidden | Blocked |
| W7-06 | SQL Injection | Request structure modification | 403 Forbidden | Blocked |

## Role 4 Analysis

All evasion techniques tested in Week 7 were successfully blocked by the WAF. This includes URL encoding, case manipulation, spacing obfuscation, tamper scripts, and request structure changes.

The consistent use of HTTP 403 (Forbidden) and 400 (Bad Request) responses indicates that the WAF was able to recognise and block malicious patterns even when they were modified.

The sqlmap tamper test is particularly important because tamper scripts are designed to bypass filters. Despite this, the WAF continued to block requests, showing strong resistance to automated evasion techniques.

These results suggest a high detection capability and strong rule coverage for the tested attack types.

## Bypass Resistance Conclusion

No successful bypasses were observed during Week 7 testing. All attack variations were blocked before reaching the application.

This indicates that the WAF is effective against common evasion techniques used in SQL Injection and Cross-Site Scripting attacks.

However, the strict blocking behaviour may increase the likelihood of false positives, which should be evaluated in later analysis.

## Limitations

- Only a limited set of evasion techniques were tested.
- Advanced or custom bypass techniques may still exist but were not explored.
- Results are based on a controlled DVWA lab environment.
