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

- `Code/`: Preserved automation and analysis scripts
- `Documentation/`: Experimental architecture, workflow and methodology documents
- `Data/`: Reviewed and processed classification results
- `Evidence/Logs/`: Preserved WAF and backend evidence
- `Evidence/Results/`: Generated metrics, CSV summaries and figures
- `Evidence/Screenshots/`: Captured experimental evidence
- `evidence_manifest.csv`: Evidence inventory and SHA-256 hashes

Raw experimental files are preserved in the original Week 5–7 project directories. Copies in the submission package are provided for examination.

WAF decisions were reviewed using available WAF and backend evidence rather than HTTP response status alone.

Cases without sufficient evidence must remain UNKNOWN/unreviewed and must not be forced into classification categories.

## Scope and Limitations

The results apply to the controlled DVWA environment, selected attack categories, generated payload transformations and tested WAF rule configurations.

The evidence package does not claim that the test results generalise to every deployment of ModSecurity or NAXSI.

Coraza is being evaluated separately by another project team member and is outside the scope of this individual technical evidence package.
