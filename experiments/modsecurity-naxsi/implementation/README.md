# ModSecurity/NAXSI Maintained Implementation

This implementation was developed through the Week 7 milestone. Milestones do
not claim historical execution.

## Objective

Actual-data metrics, missed detections, observed rule categories, latency summary and analysis report.

## Maintained implementation

This is the retained Semester 2 implementation. Earlier source snapshots were
removed after their reviewed data and final evidence had been consolidated.

## Work implemented

- Week 1: Provenance and environment review; benign ZAP/target checks.
- Week 2: Private-target configuration, ZAP settings and explicit classification methodology.
- Week 3: Seeded 600-row mixed workload derived from actual legacy templates; SQLi capture importer.
- Week 4: Original entry-point names, requests.Session through ZAP, token-aware login, session checks, scoped scans, immutable collection and audit parser.
- Week 5: Matching cases/order/proxy/authentication for both WAFs, digest checks and merge.
- Week 6: Baseline-to-variant mapping and execution through the retained pipeline.
- Week 7: Actual-data metrics, missed detections, observed rule categories, latency summary and analysis report.

## Files added

- analysis/latency_summary.py
- analysis/rule_analysis.py

## Files modified

README.md, WEEKLY_CHANGELOG.md, configuration and architecture/methodology documents.

## How to run

On Kali, Python 3.11+, from this implementation directory:

~~~bash
python zap_active_mixed_modsecurity.py --config config/test_config.json --env-file ../../../.env
~~~

For active-capable stages this defaults to a plan. Add `--execute` only after genuine
lab verification and review the configuration and methodology in this directory.

## What remains incomplete

Current VM state and real runs are not verified here. Cases, marker fixture, session,
versions and WAF routing require live review. Candidate variants need approval.
Concurrent throughput benchmarking and expanded OWASP fixtures remain future work.

## Evidence to collect

Actual configuration, commands, timestamps, corpus hashes, run manifests, authenticated
session checks and request-correlated WAF/backend logs. Generated code is not evidence
that an experiment was completed.
