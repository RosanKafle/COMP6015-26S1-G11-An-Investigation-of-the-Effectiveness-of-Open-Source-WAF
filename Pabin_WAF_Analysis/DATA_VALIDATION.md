# Data Validation and Evidence Management

**Student:** Pabin Gurung  
**Student ID:** 22343460  
**Course:** COMP6016 Computer Science Project 2  
**Group:** 11  
**Role:** Measurement, Analysis and Documentation Lead  
**Project:** An Investigation of the Effectiveness of Open-Source Web Application Firewalls

## 1. Purpose

This document records the source evidence, validation procedures, consistency checks, software tests and limitations for my individual WAF results-analysis contribution.

The work focuses on verifying reported classification totals, reviewing false negatives and ensuring that Experiment A and Experiment B are not combined incorrectly.

The original WAF testing and supporting evidence were produced by project team members. My individual contribution involves results analysis, validation, interpretation and documentation.

## 2. Evidence Sources

The principal Experiment A source is the reviewed comparison CSV from Bishal Giri's preserved group archive.

**Archive:** `COMP6016_Group11_BishalGiri_Complete_Code_Data.zip`

**Internal path:**

`Final_Submission_Complete/Project/Week_06/results/processed/comparison.csv`

**Local analysis filename:** `source_comparison.csv`

**SHA-256 checksum:**

`20154dff8b3c20580e0b94bc208d68b89dd8d34983d4e611580b308bbda021c2`

The source CSV contains 1,684 reviewed test records and has the columns:

`test_id,category,variant,modsecurity_action,naxsi_action,modsecurity_classification,naxsi_classification`

The local source CSV is excluded from this individual GitHub folder. The original group archive must remain accessible for full reproduction of the request-level validation.

## 3. Additional Supporting Evidence

Three further CSV files were extracted from the preserved group archive:

| File | Description |
|---|---|
| `transformation_detection_detail.csv` | Category-level detection counts for transformed malicious requests |
| `naxsi_fn_by_transformation.csv` | NAXSI false-negative counts grouped by transformation |
| `performance_metrics.csv` | Confusion-matrix-based classification metrics |

These files are preserved in `reviewed_group_evidence/`.

Their original location in the archive is:

`Final_Submission_Complete/Final_Analysis/Results/`

These supporting files describe Experiment A. They are not the source of Experiment B results.

## 4. Request-Level Validation

The `validate_waf_evidence.py` program reads the reviewed Experiment A comparison CSV.

It checks the presence of required columns, missing and duplicate test identifiers, total record count, recognised classification values and reported confusion-matrix totals.

The reviewed file contains 1,684 records: 1,564 malicious-labelled requests and 120 benign-labelled requests.

| Classification | ModSecurity | NAXSI |
|---|---:|---:|
| True positives | 1,564 | 1,310 |
| False negatives | 0 | 254 |
| False positives | 11 | 12 |
| True negatives | 109 | 108 |

The validation program confirmed that all eight classification counts matched the expected results and displayed `VALIDATION PASSED`.

This establishes agreement between the reviewed records and reported classification totals. It does not independently reconstruct every original WAF decision from raw logs.

## 5. NAXSI False-Negative Validation

The `analyze_naxsi_misses.py` program examined Experiment A records classified as NAXSI false negatives.

The program confirmed 254 false negatives.

### By attack category

| Category | False negatives |
|---|---:|
| XSS | 120 |
| SQL injection | 92 |
| Path traversal | 42 |
| **Total** | **254** |

### By payload variant

| Variant | False negatives |
|---|---:|
| Baseline | 42 |
| Double encoding | 212 |
| **Total** | **254** |

These results agree with the supporting `naxsi_fn_by_transformation.csv` file.

## 6. Transformation Evidence Review

The `transformation_detection_detail.csv` file was inspected separately to check the detection results for different request transformations.

The largest observed difference was associated with double encoding.

| Category | ModSecurity detected | NAXSI detected | NAXSI missed |
|---|---:|---:|---:|
| Double-encoded SQL injection | 120/120 | 28/120 | 92 |
| Double-encoded XSS | 120/120 | 0/120 | 120 |
| **Total** | **240/240** | **28/240** | **212** |

The resulting detection rates were 100% for ModSecurity and 11.67% for NAXSI within this subset.

The double-encoding totals reconcile with the 212 false negatives identified by the request-level NAXSI analysis.

The complete interpretation is documented in `TRANSFORMATION_AND_PERFORMANCE_REVIEW.md`.

These figures describe detection within the tested malicious-labelled requests, not successful exploitation.

## 7. Classification Metrics Verification

The additional `performance_metrics.csv` contains classification metrics, including precision, recall, F1-score, specificity, false-positive rate, false-negative rate and accuracy.

| Metric | ModSecurity | NAXSI |
|---|---:|---:|
| Precision | 99.30% | 99.09% |
| Recall | 100.00% | 83.76% |
| F1-score | 99.65% | 90.78% |
| Specificity | 90.83% | 90.00% |
| False-positive rate | 9.17% | 10.00% |
| False-negative rate | 0.00% | 16.24% |
| Accuracy | 99.35% | 84.20% |

These metrics are consistent with the Experiment A classification totals.

Despite its name, `performance_metrics.csv` does not contain latency, throughput, CPU usage or memory measurements.

Consequently, it cannot establish isolated WAF processing overhead.

## 8. Aggregate Results Analysis

The `analyze_waf_results.py` program reads `reported_aggregates.json`.

It calculates recall, precision, false-positive rate and accuracy, then generates `waf_comparison.csv` and `waf_detection_chart.png`.

The aggregates represent two different evaluations:

- **Experiment A:** 1,684 reviewed requests per WAF for ModSecurity and NAXSI.
- **Experiment B:** 111 reported requests per WAF for ModSecurity, Coraza and NAXSI.

The experiments are reported separately because their datasets and conditions differ.

Experiment B currently uses reported aggregate totals and has not been independently reconciled against the latest complete request-level evidence.

The chart presents classification results, not system performance or isolated latency overhead.

## 9. Software Testing and Error Handling

The three Python programs were syntax-checked and executed successfully.

The aggregate-analysis program was tested with a negative true-positive count in a temporary input file. The invalid value was rejected.

The request-level validator was tested using a modified temporary CSV containing a duplicate test identifier. The program rejected it with:

`ValueError: Duplicate test IDs found`

The temporary test file was kept separate from the original source CSV.

A successful request-level validation output is preserved in `validation_results.txt`.

The NAXSI missed-detection output is preserved in `naxsi_misses_results.txt`.

These tests demonstrate selected input checks and successful processing of the reviewed data. They are not a comprehensive automated test suite covering all possible malformed inputs.

## 10. Data Integrity and Management

The original evidence archive was preserved without alteration.

The reviewed request-level comparison file was extracted into a separate local working copy.

A SHA-256 checksum was recorded for that file to support identification and subsequent integrity checks.

The three additional group summary CSVs were also copied into a separate inspection folder before being included in `reviewed_group_evidence/`.

The project uses controlled laboratory applications and WAF configurations. The analysis contribution does not require production credentials or personal information.

Raw logs and test evidence should remain available in the group's preserved submission package where needed for supervisor inspection.

## 11. Reproducibility

The analysis was executed on macOS using Python 3.13.7 and Matplotlib.

To reproduce the aggregate results:

```bash
python3 analyze_waf_results.py
```

To reproduce the Experiment A classification validation after obtaining the reviewed comparison CSV:

```bash
python3 validate_waf_evidence.py source_comparison.csv
```

To reproduce the NAXSI false-negative breakdown:

```bash
python3 analyze_naxsi_misses.py
```

The original group archive is necessary for a complete re-run of the two request-level programs because `source_comparison.csv` is not included in the individual GitHub folder.

## 12. Known Limitations

The principal limitations are:

- Validation checks consistency with reviewed labels; it does not independently adjudicate all original WAF and Apache logs.
- False negatives identify malicious-labelled requests that were allowed, not confirmed exploitation.
- The tested corpus and WAF configurations limit generalisation.
- Transformation groups contain different numbers of requests.
- Experiment A and Experiment B cannot be pooled into a single overall performance estimate.
- Classification metrics must not be interpreted as latency, throughput or resource overhead.
- Experiment B aggregate figures still require independent reconciliation with the latest request-level records.

## 13. Outcome and Future Verification

The Experiment A request-level classifications matched the reported confusion-matrix totals.

The NAXSI missed-detection analysis identified 254 false negatives, including 212 double-encoded requests and 42 baseline path-traversal requests.

The additional group evidence was consistent with these findings and clarified the distinction between classification effectiveness and system performance.

Further verification could include checking individual decisions against preserved raw logs, examining updated Experiment B evidence and evaluating latency overhead using appropriately controlled timing data.
