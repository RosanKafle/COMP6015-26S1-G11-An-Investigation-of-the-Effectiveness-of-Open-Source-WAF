# Week 9 – Final Results and Analysis

## 1. Detection and Evasion Results Preserved in Docs

| Test ID | Attack Type   |     Variation          | Tool   | Result  | Notes                     |
|---------|---------------|------------------------|--------|---------|---------------------------|
| W7-01   | SQL Injection | URL encoding           | Burp   | Blocked | 403 Forbidden             |
| W7-02   | SQL Injection | Case/spacing variation | Burp   | Blocked | 403 Forbidden             |
| W7-03   | SQL Injection | Tamper script          | sqlmap | Blocked | 403 Forbidden (149 times) |
| W7-04   | XSS           | URL encoding           | Burp   | Blocked | 400 Bad Request           |
| W7-05   | XSS           | Case variation         | Burp   | Blocked | 403 Forbidden             |
| W7-06   | SQL Injection | Request structure      | Burp   | Blocked | 403 Forbidden             |

### Detection Rate

Total tests: 6  
Blocked: 6  

**Detection Rate = 100% across the six selected Week 7 ModSecurity cases documented in the Week 7 evidence set**

Support note:
`W7-06` is preserved only as a matrix summary entry, while the other Week 7 cases are backed by dedicated raw notes or raw tool output files.

## 2. Cross-WAF SQLi Comparison from Week 6

- ModSecurity sqlmap run: no injectable parameter detected, `500` returned 908 times
- Coraza sqlmap run: no injectable parameter detected, `403` returned 909 times
- Evidence source:
  - `../week6/sqlmap-waf1-week6.txt`
  - `../week6/sqlmap-waf2.txt`

This supports a narrow Week 6 conclusion: both WAF paths disrupted the saved automated SQLi run, and the Coraza path produced a cleaner explicit block response in the exported evidence.

---

## 3. Performance Comparison from Saved Week 8 Raw Files

| Metric | Baseline saved run | ModSecurity saved run | Coraza saved run |
|--------|--------------------|-----------------------|------------------|
| Requests/sec | 13800.72 | 2157.59 | 159.20 |
| Time/request | 0.725 ms | 4.635 ms | 62.812 ms |
| Failed requests | 0 | 0 | 0 |
| Non-2xx responses | 100 | 100 | 0 reported |
| Document length | 0 bytes | 0 bytes | 6436 bytes |

---

## 4. Analysis

The saved evidence shows a consistent protection trend, but the strength of that conclusion depends on the test set. Manual Week 3 testing confirmed that DVWA was vulnerable without a WAF. In Week 6, both WAF paths disrupted the preserved automated sqlmap SQL injection run. In Week 7, all six selected obfuscated SQLi and XSS cases documented in the evidence set were blocked on the ModSecurity path, although `W7-06` is preserved only as a matrix summary entry.

The saved Week 8 raw files also suggest a performance trade-off. However, the preserved ApacheBench runs are not a fully normalized benchmark because the saved baseline and ModSecurity runs returned zero-byte non-2xx responses, while the saved Coraza run returned a full page body. The safest evidence-backed statement is that the saved Coraza path showed the lowest throughput and highest latency in this exported dataset.

This indicates that WAF protection can add measurable request-processing overhead, but stronger matched performance testing would be needed for a strict head-to-head benchmark.

---

## 5. Key Findings

- Manual baseline testing confirmed that DVWA was vulnerable without WAF protection.
- Both WAF paths disrupted the saved Week 6 automated sqlmap SQL injection run.
- ModSecurity blocked all six selected Week 7 obfuscated SQLi and XSS cases preserved in the docs export.
- No successful bypass is preserved in the current docs set.
- The saved Week 8 files suggest added overhead on protected paths, with the highest saved latency on the Coraza path.

---

## 6. Limitations

- Testing was conducted in a controlled lab environment using DVWA.
- The stored automated Week 3 sqlmap baseline was not a clean authenticated exploit proof because the saved output still redirected to `login.php`.
- The detailed Week 7 evasion set is preserved only for ModSecurity, not for both WAFs equally.
- False positive testing was basic and based on manual interaction summary rather than exported per-request captures.
- The saved Week 8 performance runs were not fully normalized across authentication state and response body size.
- Results may vary depending on WAF configuration and real-world traffic conditions.

---

## 7. Conclusion

The exported evidence supports a conservative conclusion: in this DVWA lab, both ModSecurity and Coraza interfered with the saved automated SQLi probes, and ModSecurity blocked all preserved Week 7 obfuscated SQLi and XSS cases. The saved performance files also suggest overhead on protected paths, although a stricter benchmark would require more closely matched runs. The final report should present these findings with those limits stated clearly.
