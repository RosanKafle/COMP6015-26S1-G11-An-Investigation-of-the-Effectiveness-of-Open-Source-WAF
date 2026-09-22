# Actual cumulative snapshot lineage

Computed from the revised files. An unchanged path retains byte-identical content.
All previous paths must exist in the next milestone; modified files are listed below.

| Snapshot | Files | Added | Modified | Unchanged | Removed |
|---|---:|---:|---:|---:|---:|
| Week_01 | 18 | 18 | 0 | 0 | 0 |
| Week_02 | 23 | 5 | 2 | 16 | 0 |
| Week_03 | 35 | 12 | 2 | 21 | 0 |
| Week_04 | 54 | 19 | 2 | 33 | 0 |
| Week_05 | 61 | 7 | 2 | 52 | 0 |
| Week_06 | 67 | 6 | 2 | 59 | 0 |
| Week_07 | 74 | 7 | 3 | 64 | 0 |

## Week_01

Added:

- .env.example
- .gitignore
- README.md
- WEEKLY_CHANGELOG.md
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
- requirements.txt
- scripts/check_environment.py
- scripts/lab_http.py

Modified:


## Week_02

Added:

- config/test_config.json
- docs/classification_rules.md
- docs/methodology.md
- docs/test_workflow.md
- scripts/config_loader.py

Modified:

- README.md
- WEEKLY_CHANGELOG.md

## Week_03

Added:

- config/corpus_manifest.json
- config/inherited_test_templates.json
- outputs/test_inventory.csv
- scripts/build_mixed_corpus.py
- scripts/import_zap_capture.py
- scripts/test_loader.py
- test_cases/README.md
- test_cases/command_injection.csv
- test_cases/normal.csv
- test_cases/path_traversal.csv
- test_cases/sqli.csv
- test_cases/xss.csv

Modified:

- README.md
- WEEKLY_CHANGELOG.md

## Week_04

Added:

- automate_modsecurity_sqli.py
- docs/evidence_review.md
- logs/README.md
- reports/README.md
- results/processed/README.md
- results/raw/README.md
- run_all_modsecurity_tests.py
- scripts/apply_evidence.py
- scripts/classification.py
- scripts/dvwa_session.py
- scripts/parse_modsecurity_audit.py
- scripts/request_runner.py
- scripts/result_reader.py
- scripts/result_writer.py
- scripts/run_test_set.py
- scripts/zap_active_pipeline.py
- scripts/zap_client.py
- zap_active_master_modsecurity.py
- zap_active_mixed_modsecurity.py

Modified:

- README.md
- WEEKLY_CHANGELOG.md

## Week_05

Added:

- analysis/README.md
- analysis/comparison_template.csv
- analysis/merge_results.py
- config/modsecurity.example.json
- config/naxsi.example.json
- scripts/run_comparison.py
- zap_active_mixed_naxsi.py

Modified:

- README.md
- WEEKLY_CHANGELOG.md

## Week_06

Added:

- docs/obfuscation_methodology.md
- outputs/variant_inventory.csv
- scripts/generate_variants.py
- scripts/payload_variants.py
- test_cases/variants/README.md
- test_cases/variants/generated_variants.csv

Modified:

- README.md
- WEEKLY_CHANGELOG.md

## Week_07

Added:

- analysis/category_summary.py
- analysis/confusion_matrix.py
- analysis/generate_analysis_report.py
- analysis/latency_summary.py
- analysis/metrics.py
- analysis/missed_detection_analysis.py
- analysis/rule_analysis.py

Modified:

- README.md
- WEEKLY_CHANGELOG.md
- analysis/README.md
