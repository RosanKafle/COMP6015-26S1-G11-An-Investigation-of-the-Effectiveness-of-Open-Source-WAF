# Week 02 Evaluation Design

## Focus

Define the evaluation method, select the WAF/application stack, and prepare the data collection template.

## Selected Test Direction

The project uses DVWA as the vulnerable application and ModSecurity with OWASP CRS as the main WAF. Coraza is included later as the second WAF for comparison.

## Evaluation Criteria

The evaluation records:

- Tool or manual method used.
- Payload type and target page.
- WAF mode or WAF name.
- HTTP response code.
- Whether the request was allowed, detected, blocked, or disrupted.
- Notes from application response and WAF logs.

## Planned Attack Categories

- SQL Injection.
- Cross-Site Scripting.
- Command Injection.
- Directory Traversal.
- Automated scanning with SQLMap, Nikto, Wapiti, ZAP, and Burp Suite where applicable.

## Week 02 Outputs

- Methodology direction.
- Metrics/data collection format.
- DVWA target selection.
- Initial OWASP and WAFEC-style evaluation criteria.

