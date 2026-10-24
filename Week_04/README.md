# Week 4: Improve existing ZAP Python pipelines

Current catch-up implementation. Milestones do not claim historical execution.

## Objective

Original entry-point names, requests.Session through ZAP, token-aware login, session checks, scoped scans, immutable collection and audit parser.

## Built on previous week

Built on Week_03. Retains Kali -> ZAP -> Ubuntu, existing DVWA /DVWA/,
source references and earlier capabilities. No sibling week is imported at runtime.

## Work implemented

- Week 1: Provenance and environment review; benign ZAP/target checks.
- Week 2: Private-target configuration, ZAP settings and explicit classification methodology.
- Week 3: Seeded 600-row mixed workload derived from actual legacy templates; SQLi capture importer.
- Week 4: Original entry-point names, requests.Session through ZAP, token-aware login, session checks, scoped scans, immutable collection and audit parser.

## Files added

- automate_modsecurity_sqli.py
- run_all_modsecurity_tests.py
- scripts/dvwa_session.py
- scripts/parse_modsecurity_audit.py
- scripts/request_runner.py
- scripts/result_writer.py
- scripts/run_test_set.py
- scripts/zap_active_pipeline.py
- scripts/zap_client.py
- zap_active_master_modsecurity.py
- zap_active_mixed_modsecurity.py

## Files modified

README.md, WEEKLY_CHANGELOG.md, configuration and architecture/methodology documents.
See root docs/snapshot_lineage.md for actual adjacent-snapshot file changes.
The earlier generated implementation is archived; original semester files are untouched.

## How to run

On Kali, Python 3.11+, from this week directory:

~~~bash
python zap_active_mixed_modsecurity.py --config config/test_config.json --env-file ../.env
~~~

For active-capable stages this defaults to a plan. Add --execute only after genuine
lab verification. Root VM_SETUP_STEP_BY_STEP.md provides full commands and checkpoints.

## What remains incomplete

Current VM state and real runs are not verified here. Cases, marker fixture, session,
versions and WAF routing require live review. Candidate variants need approval.
Concurrent throughput benchmarking and expanded OWASP fixtures remain future work.

## Evidence to collect

Actual configuration, commands, timestamps, corpus hashes, run manifests, authenticated
session checks and request-correlated WAF/backend logs. Generated code is not evidence
that an experiment was completed.
