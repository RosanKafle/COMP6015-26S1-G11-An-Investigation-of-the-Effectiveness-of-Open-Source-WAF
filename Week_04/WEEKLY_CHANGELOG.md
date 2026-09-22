# Week 4 Changelog

## Objective

Improve existing ZAP Python pipelines

## Built on previous week

Built on Week_03; retains inherited topology, source lineage and earlier capabilities.

## Added this week

Original entry-point names, requests.Session through ZAP, token-aware login, session checks, scoped scans, immutable collection and audit parser.

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

## Modified this week

Configuration and milestone documentation; refactored shared modules where applicable.
Original files remain unchanged.

## Current capabilities

- Week 1: Provenance and environment review; benign ZAP/target checks.
- Week 2: Private-target configuration, ZAP settings and explicit classification methodology.
- Week 3: Seeded 600-row mixed workload derived from actual legacy templates; SQLi capture importer.
- Week 4: Original entry-point names, requests.Session through ZAP, token-aware login, session checks, scoped scans, immutable collection and audit parser.

## Not yet completed

Live configuration checks, actual experiments and evidence-based conclusions.
Variants require semantic review; expanded fixtures and concurrent benchmarks deferred.

## Evidence to collect

Real commands, versions, corpus hashes, ZAP configuration, sessions, HTTP responses,
WAF/backend logs and reviewed outcomes. No invented dates, screenshots or results.
