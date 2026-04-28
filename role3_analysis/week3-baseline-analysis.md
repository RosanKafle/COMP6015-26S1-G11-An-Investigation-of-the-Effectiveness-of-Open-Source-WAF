# Week 3 Baseline Analysis

## Purpose
Week 3 focused on reviewing baseline security behaviour before WAF blocking was fully evaluated. Role 3 provided raw outputs from sqlmap, Wapiti, and rule-tuning notes. My role was to organise these results, classify the findings, and identify which evidence can be used in the final report.

## Files reviewed
- sqlmap-baseline.txt
- sqlmap-low.txt
- sqlmap-fixed.txt
- sqlmap-tamper.txt
- sqlmap-week3.txt
- wapiti-week3.txt
- week3_before_after_comparison.txt
- week3_precision_recall.txt
- week3_rule_rationale.md
- status.md

## Week 3 Findings Table

| Evidence file            | Tool / Method | Main finding | Classification | Use in report |
|--------------------------|---------------|--------------|----------------|---------------|
| sqlmap-baseline.txt | sqlmap | Parameters were tested but not confirmed injectable | Inconclusive / No SQLi confirmed | Baseline SQLi testing evidence |
| sqlmap-low.txt | sqlmap | `id` and `Submit` parameters were not confirmed injectable | Inconclusive / No SQLi confirmed | Shows initial automated SQLi testing limitation |
| sqlmap-tamper.txt | sqlmap tamper | Tamper run failed due to SSL connection issue | Failed test | Mention as limitation |
| wapiti-week3.txt | Wapiti | Found CSP, clickjacking, MIME, HTTP, and cookie security issues | Security misconfiguration findings | Baseline vulnerability scan evidence |
| week3_precision_recall.txt | Rule tuning notes | Lower threshold improves recall; higher threshold improves precision but may miss smaller attacks | Analysis note | Use in methodology/discussion |
| week3_rule_rationale.md | Suricata rule notes | SYN scan and repeated SSH attempt rules were created and threshold-tested | Detection rule rationale | Use as supporting detection analysis |

## Role 4 Analysis

The sqlmap results did not confirm SQL Injection in the automated Week 3 runs. Several files show that sqlmap tested the `id` and `Submit` parameters, but the parameters were reported as not injectable. This does not prove that DVWA has no SQL Injection vulnerability; it shows that the automated scan configuration did not successfully confirm injection during this run.

The Wapiti scan found several baseline web security weaknesses, mainly missing security headers and insecure cookie or HTTP configuration. These are useful for the baseline section because they show the application had security weaknesses before WAF evaluation.

The tuning notes are useful for the analysis section because they explain the relationship between detection sensitivity, precision, recall, and false positives. Lower thresholds detect more suspicious activity but may create more noise, while higher thresholds reduce noise but risk missing slower or smaller attacks.

Overall, Week 3 should be treated as baseline evidence and methodology preparation, not final WAF effectiveness evidence.

## Week 3 Limitations

- sqlmap did not confirm SQL Injection in the uploaded automated scan outputs.
- The tamper test failed because of an SSL connection issue.
- Wapiti crawled only a limited scope and mainly identified configuration weaknesses.
- These results should be used as baseline evidence, not as proof that the WAF blocked attacks.
