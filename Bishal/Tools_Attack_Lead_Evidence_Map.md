# Tools and Attack Lead Evidence Map

Source branch:

https://github.com/RosanKafle/COMP6015-26S1-G11-An-Investigation-of-the-Effectiveness-of-Open-Source-WAF/tree/Tools-Attack-Lead

Branch commit used:

`ec85294170df7f111cc05616f2fd935c94d7434b`

Clean local copy:

`Tools_Attack_Lead_Evidence/`

## Role Alignment

This evidence supports the Tools and Attack Lead role. The role focuses on offensive testing, scanner use, attack payloads, baseline testing, WAF comparison, evasion testing, and performance/load testing support.

## Weekly Mapping

| Week | Tools/Attack Lead evidence | Local folder |
|---|---|---|
| Week 03 | Baseline SQLMap output, Wapiti baseline report, scanner notes, precision/recall notes | `Week 03/tool-output/github_tools_attack_lead_week3/` |
| Week 04 | ModSecurity detection-mode status note | `Week 04/tool-output/github_tools_attack_lead_week4/` |
| Week 05 | Blocking-mode status note and SQLMap blocking progression | `Week 05/tool-output/github_tools_attack_lead_week5/` |
| Week 06 | ModSecurity SQLMap output, Coraza SQLMap output, Wapiti WAF2 report, WAF comparison notes | `Week 06/tool-output/github_tools_attack_lead_week6/` |
| Week 07 | Burp SQL injection notes, evasion test matrix, SQLMap tamper output, session artifacts | `Week 07/tool-output/github_tools_attack_lead_week7/` |
| Week 09 | Baseline, ModSecurity, and Coraza ApacheBench load results; light attack under load notes | `Week 09/tool-output/github_tools_attack_lead_week8_performance/` |
| Week 10 | Coraza/WAF2 SQLMap, Wapiti, and load-test evidence reused for final second-WAF evidence | `Week 10/tool-output/github_coraza_waf2_evidence/` |

## Tool Coverage

- SQLMap: baseline, WAF #1, WAF #2, and tamper-script testing.
- Wapiti: baseline report and WAF #2 report.
- Burp Suite: encoded SQL injection and evasion request notes.
- ApacheBench: no-WAF, ModSecurity, and Coraza load testing.
- Coraza/WAF #2: SQLMap, Wapiti, and performance evidence.

## Key Files

- `Tools_Attack_Lead_Evidence/week3/sqlmap-baseline.txt`
- `Tools_Attack_Lead_Evidence/week3/sqlmap-fixed.txt`
- `Tools_Attack_Lead_Evidence/week3/sqlmap-tamper.txt`
- `Tools_Attack_Lead_Evidence/week3/wapiti-baseline.html/report.html`
- `Tools_Attack_Lead_Evidence/week6/sqlmap-waf1-week6.txt`
- `Tools_Attack_Lead_Evidence/week6/sqlmap-waf2.txt`
- `Tools_Attack_Lead_Evidence/week6/wapiti-waf2.txt`
- `Tools_Attack_Lead_Evidence/week7/week7-test-matrix.md`
- `Tools_Attack_Lead_Evidence/week7/sqlmap/W7-03-sqlmap-tamper-space2comment.txt`
- `Tools_Attack_Lead_Evidence/week8/performance-results.md`

