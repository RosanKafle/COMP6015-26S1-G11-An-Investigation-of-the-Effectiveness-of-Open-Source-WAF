# Open-Source WAF Effectiveness Investigation

## Project Overview

This project investigates the effectiveness of open-source web application firewalls against malicious HTTP requests, including SQL injection, cross-site scripting, command injection and path traversal.

This evidence package focuses on the ModSecurity and NAXSI experiments and the corresponding infrastructure, request classification and performance analysis.

## Experimental Environment

- Testing client: Kali Linux
- Target application: DVWA
- Backend web server: Apache
- WAF implementations: ModSecurity with OWASP CRS and NAXSI with Nginx
- Testing approach: Matched request corpus with baseline and transformed payloads
- Evaluation method: Correlated WAF and backend evidence

## Experimental Dataset

The final reviewed comparison contains 1,684 requests per WAF, including 1,564 malicious requests and 120 normal requests.

Both WAFs were evaluated using the same matched request corpus.

## Reviewed Results

| Metric | ModSecurity | NAXSI |
|---|---:|---:|
| True positives | 1,564 | 1,310 |
| True negatives | 109 | 108 |
| False positives | 11 | 12 |
| False negatives | 0 | 254 |
| Recall | 100% | 83.76% |
| Precision | 99.30% | 99.09% |

## Significant Findings

NAXSI missed 254 malicious requests. These comprised 212 double-encoded SQL injection and XSS requests and 42 baseline path-traversal requests.

For the 240 double-encoded malicious requests, ModSecurity detected 240 while NAXSI detected 28.

These findings describe the tested configurations and corpus. They do not establish universal product performance or confirm that every allowed malicious request successfully exploited the backend application.

## Evidence and Reproducibility

- `Results/`: Generated metrics, CSV summaries, figures and their analysis scripts.
- `../../Week_07/results/final/`: Reviewed request-level ModSecurity/NAXSI results and final comparisons.
- `../COMP6016_Group11_BishalGiri_Complete_Code_Data.zip`: Preserved Week 1–7 code, raw requests and responses, correlated WAF/backend logs, processed data and the original final-analysis package.
- `../../Pabin_WAF_Analysis/reviewed_group_evidence/`: Independently reviewed supporting summaries.

The retained ZIP has SHA-256
`3b05598679870830061df7450aae3eb5bc4f8c7217eafe0ab4db5ef1b0d90575`.
Its original CSV byte hashes differ from some working-tree copies because Git
normalised line endings; the reviewed CSV rows were checked as semantically
identical during repository cleanup.

The ZIP contains private RFC1918 laboratory addresses used for experimental
provenance. A targeted publication review found no private keys, GitHub or AWS
tokens, bearer/authorization headers, ZAP API keys or retained PHP session IDs.
The archive must still be kept with the evidence package because it contains raw
logs that are not duplicated elsewhere in the cleaned tree.

WAF decisions were reviewed using available WAF and backend evidence rather than HTTP response status alone.

Cases without sufficient evidence must remain UNKNOWN/unreviewed and must not be forced into classification categories.

## Scope and Limitations

The results apply to the controlled DVWA environment, selected attack categories, generated payload transformations and tested WAF rule configurations.

The evidence package does not claim that the test results generalise to every deployment of ModSecurity or NAXSI.

Coraza is being evaluated separately by another project team member and is outside the scope of this individual technical evidence package.
