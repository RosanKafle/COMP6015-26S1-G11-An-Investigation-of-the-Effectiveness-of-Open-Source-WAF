# Week 1: Review inherited Kali ZAP and Ubuntu lab

Current catch-up implementation. Milestones do not claim historical execution.

## Objective

Provenance and environment review; benign ZAP/target checks.

## Built on previous week

Built on the previous semester final report and original ZAP framework. Retains Kali -> ZAP -> Ubuntu, existing DVWA /DVWA/,
source references and earlier capabilities. No sibling week is imported at runtime.

## Work implemented

- Week 1: Provenance and environment review; benign ZAP/target checks.

## Files added

- config/environment.example.json
- config/waf_inventory.json
- docs/architecture.md
- docs/environment_inventory.md
- docs/experimental_scope.md
- legacy_reference/README.md
- legacy_reference/automate_modsecurity_sqli.py.txt
- legacy_reference/run_all_modsecurity_tests.py.txt
- legacy_reference/source_manifest.json
- legacy_reference/zap_active_master_modsecurity.py.txt
- legacy_reference/zap_active_mixed_modsecurity.py.txt
- scripts/check_environment.py

## Files modified

README.md, WEEKLY_CHANGELOG.md, configuration and architecture/methodology documents.
See root docs/snapshot_lineage.md for actual adjacent-snapshot file changes.
The earlier generated implementation is archived; original semester files are untouched.

## How to run

On Kali, Python 3.11+, from this week directory:

~~~bash
python scripts/check_environment.py --config config/environment.example.json
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
