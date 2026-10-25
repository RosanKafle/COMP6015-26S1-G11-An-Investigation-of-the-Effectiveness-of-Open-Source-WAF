# Continue the final report methodology

Retain the inherited SQLi replay, ZAP active-scanning and authenticated mixed-traffic
pipelines. Their outputs represent separate experiments; do not pool them.

1. Inventory Kali, Ubuntu, ZAP, Apache/ModSecurity/CRS, Nginx/NAXSI and existing DVWA.
2. Verify host-only routing, blocking mode and the DVWA Low security setting.
3. Review inherited cases and calibrate intended application behaviour in a separately
   documented WAF-off condition. Create only the harmless lab marker file.
4. Freeze the seeded corpus: 120 normal plus 120 per attack category, 600 total.
   Repeated templates are not independent payloads. Label smaller pilots explicitly.
5. Record versions, rule settings, thresholds, exclusions, corpus digest and condition.
6. Log in through the WAF using the current hidden form token and browser headers.
   Maintain/recheck the session. Extra auth-* requests are outside the labelled corpus.
7. Send each labelled request once through Kali ZAP, without following redirects.
   Save response bytes, real elapsed time, metadata and X-Lab-Request-ID.
8. Match each request with WAF/backend logs. Review candidate audit interventions;
   whole-log counts and response status alone do not establish a WAF action.
9. Derive TP/TN/FP/FN only from known expected class and supported action.
   Preserve errors, skipped cases and uncertain observations as UNKNOWN.
10. Repeat unchanged cases/order/rate through NAXSI. Verify no second enforcing WAF
    in the backend path. Re-login after changing conditions and record session renewals.
11. Generate/review controlled variants and run them through the same pipeline.
12. Analyse real reviewed CSVs, observed rule IDs and response times with provenance.

ZAP active scanning is exploratory and contains discovery requests. Alerts are not
WAF detections. Review exported requests before making them a labelled replay corpus.
Do not infer detected attack category from the input label. Multiple rule groups
can match one request; missing rule events do not prove allowance.

The 600-row shape restores the old experiment design, not byte-for-byte equivalence.
Method fixes, harmless fixtures, seeded ordering and classification changes must be
disclosed when discussing historical results. Repetitions and threshold tuning need
new recorded conditions. Concurrent throughput/load benchmarking and expanded OWASP
fixtures remain future experiments; current timings include ZAP/network/backend cost.
