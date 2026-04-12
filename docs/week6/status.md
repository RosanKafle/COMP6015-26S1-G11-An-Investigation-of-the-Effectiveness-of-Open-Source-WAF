# Week 6: Introduce WAF #2 (Coraza)

## What I did (Tools / Offensive role)
- Confirmed WAF #1 (ModSecurity) still blocked sqlmap on DVWA.
- Deployed WAF #2 using Coraza + CRS (nginx container) in front of DVWA.
- Ran the same sqlmap SQLi test through WAF #2 at http://localhost:8080.
- Saved raw outputs:
  - sqlmap-waf1-week6.txt (WAF #1)
  - sqlmap-waf2.txt (WAF #2)
- Wrote baseline-waf2-results.md comparing baseline, WAF #1, and WAF #2.

## Key observations (first pass)
- Baseline (no WAF): DVWA SQLi was exploitable with sqlmap. [fill from Week 3 notes]
- WAF #1 (ModSecurity): sqlmap could not find an injectable parameter, many 500 errors.
- WAF #2 (Coraza): [briefly summarise what sqlmap did – blocked, errors, or allowed more].
- No tuning applied yet to WAF #2 (this week is initial behaviour only, as per project brief).

## Next steps
- Week 7: Try more advanced and obfuscated attacks against both WAFs, and document any bypasses.
