# Continuity with the final previous semester report

The newly supplied final report is the baseline for this revision. The original
scripts in WAF ModSec Final/zap-waf-framework are byte-identical to the matching
four files in the supplied Third Semester work/zap-waf-framework directory.
Their original hashes and redacted review copies appear in every legacy_reference/.
The actual source constants supply config/inherited_test_templates.json.

| Prior work | Retained | Improvement and milestone |
|---|---|---|
| Report Sections 3–4 | Kali DFIR01, host-only network, Ubuntu, Apache/ModSecurity, DVWA, installed ZAP | Week 1 fresh inventory; no replacement VM/container stack |
| Sections 5 and 10.3 | Labelled traffic, CSVs, WAF logs and classifications | Week 2 common decisions, unknowns and provenance |
| zap_active_mixed_modsecurity.py ATTACKS/NORMAL_REQUESTS | Endpoint and payload families, normal browsing, 120 samples/class | Week 3 explicit input files, source IDs and recorded seed |
| Mixed pipeline session/proxy | requests.Session, browser headers, Kali ZAP proxy | Week 4 token-aware login, periodic auth checks and real timings |
| automate_modsecurity_sqli.py | SQLi replay and existing captured-message input path | Week 3 reviewed capture importer; Week 4 replay uses shared session/collector |
| zap_active_master_modsecurity.py | Spider, selected scanners, message/alert exports | Week 4 exact context, bounded scans, private API key, own scan-message IDs and cleanup |
| run_all_modsecurity_tests.py | Separate attack-only batch | Week 4 explicit exclusion of normal cases; no merging with mixed cohort |
| Section 11.1 | Planned NAXSI comparison | Week 5 same corpus/order/digest and proxy/auth path |
| Baseline payload families | SQLi/XSS baseline intent | Week 6 controlled transformations and parent mapping |
| Sections 7 and 10.3 | Metrics, classifications and rule activity | Week 7 real-log rule IDs, multiple observed categories, misses/FPs and latency |

## Corrections are explicit

- A recorded seed replaces unrecorded random choices. The same corpus is sent to both WAFs.
- Command injection now uses the DVWA POST form and harmless marker output.
- Traversal reads a created marker file, not system-data files.
- Real login replaces a stale embedded PHPSESSID; auth checks are extra unlabelled traffic.
- Observed rule categories replace the old shortcut that copied expected categories
  into detected categories whenever the status indicated blocking.
- Audit transactions replace whole-log grep counts for run-specific rule evidence.
- HTTP 403/406 are observations, not automatic true positives.
- False-positive rate is N/A without normal observations, not zero.

These changes prevent a claim of byte-identical reproduction. Re-establish the
ModSecurity baseline before making a new matched NAXSI comparison.

## Reconcile the historical evidence

The final report directory contains a 600-row mixed detail file consistent with its
summary: 120 normal and 480 malicious. Its classification matrix has 120 per attack
category. Its 300-per-category attack matrix is from a separate 1,200-request batch.
Section 7.5 must not be read as the breakdown of the 600-row run.

The earlier supplied folder also contains later XSS-only NAXSI material. That does
not establish a matched NAXSI run for this final report's mixed workload. Keep it as
a separate historical study. New results are generated only by actual execution.

This repository improves the inherited workflow and task structure; the entry-point
files delegate repeated logic to readable modules rather than duplicating the old
code's session, classification and output errors.
