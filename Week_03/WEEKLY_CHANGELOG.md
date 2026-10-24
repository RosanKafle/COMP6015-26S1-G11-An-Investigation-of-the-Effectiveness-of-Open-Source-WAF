# Week 3 Changelog

## Objective

Freeze inherited mixed traffic corpus

## Built on previous week

Built on Week_02; retains inherited topology, source lineage and earlier capabilities.

## Added this week

Seeded 600-row mixed workload derived from actual legacy templates; SQLi capture importer.

- config/inherited_test_templates.json
- scripts/build_mixed_corpus.py
- scripts/import_zap_capture.py
- scripts/test_loader.py

## Modified this week

Configuration and milestone documentation; refactored shared modules where applicable.
Original files remain unchanged.

## Current capabilities

- Week 1: Provenance and environment review; benign ZAP/target checks.
- Week 2: Private-target configuration, ZAP settings and explicit classification methodology.
- Week 3: Seeded 600-row mixed workload derived from actual legacy templates; SQLi capture importer.

## Not yet completed

Live configuration checks, actual experiments and evidence-based conclusions.
Variants require semantic review; expanded fixtures and concurrent benchmarks deferred.

## Evidence to collect

Real commands, versions, corpus hashes, ZAP configuration, sessions, HTTP responses,
WAF/backend logs and reviewed outcomes. No invented dates, screenshots or results.
