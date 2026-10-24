# WAF Data Validation

**Project:** An Investigation of the Effectiveness of Open-Source Web Application Firewalls  
**Student:** Pabin Gurung (22343460)  
**Role:** Measurement, Analysis and Documentation Lead

## 1. Purpose

This document explains how I checked the WAF analysis results against the reviewed experimental data.

The main objective was to identify errors in the dataset, check the reported classification counts and record the limitations of the analysis.

## 2. Source Data

The analysis used two input sources.

The first was `reported_aggregates.json`, containing previously reported figures for Experiments A and B.

The second was the reviewed Experiment A classification file, `comparison.csv`, obtained from the group evidence archive:

`COMP6016_Group11_BishalGiri_Complete_Code_Data.zip`

Original archive path:

`Final_Submission_Complete/Project/Week_06/results/processed/comparison.csv`

A local copy was saved as `source_comparison.csv`.

The file contained 1,684 request records.

SHA-256 checksum:

`20154dff8b3c20580e0b94bc208d68b89dd8d34983d4e611580b308bbda021c2`

## 3. Analysis and Validation

Two Python programs were used.

`analyze_waf_results.py` calculates recall, precision, false-positive rate and accuracy using the previously reported confusion-matrix figures. It generates a comparison CSV and chart.

`validate_waf_evidence.py` checks the reviewed Experiment A records.

The request-level validator checks:

- Required CSV columns.
- Missing test identifiers.
- Duplicate test identifiers.
- The expected number of records.
- Invalid classification labels.
- Agreement between recalculated classification counts and reported totals.

The aggregate-analysis program rejects negative counts and mismatched experiment totals. It does not yet enforce integer-only input types.

## 4. Validation Results

The reviewed Experiment A dataset contained 1,684 requests per WAF.

| Classification | ModSecurity | NAXSI |
|---|---:|---:|
| True positives | 1,564 | 1,310 |
| True negatives | 109 | 108 |
| False positives | 11 | 12 |
| False negatives | 0 | 254 |

All eight classification counts matched the previously reported results.

The validation program displayed `VALIDATION PASSED`.

## 5. Negative Testing

I tested the programs using deliberately modified input data.

**Test 1 — Negative count**

A negative true-positive value was introduced into a temporary copy of the aggregate dataset.

The analysis program rejected this value with:

`ValueError: Counts cannot be negative`

The original dataset was restored and analysed successfully afterward.

**Test 2 — Duplicate request ID**

A separate copy of the reviewed comparison CSV was modified so that two records had the same test identifier.

The request-level validator rejected the modified dataset with:

`ValueError: Duplicate test IDs found`

The original source file was not modified.

## 6. Experiment Separation

Experiment A contains 1,684 reviewed requests per WAF and compares ModSecurity with NAXSI.

Experiment B is a separate controlled evaluation involving ModSecurity, Coraza and NAXSI, with 87 malicious and 24 benign confirmed observations per WAF in the previously reported R11/R12 summary.

The two experiments use different datasets and must not be combined.

The newer R11/R12 evidence has not yet been reconciled through this validation workflow.

## 7. Limitations

The Experiment A validation confirms consistency between the reviewed classification records and the group's reported totals. It does not independently establish that every WAF decision was correctly classified.

The original WAF audit logs and backend response evidence have not been independently checked for every request in this individual workflow.

An allowed malicious-labelled request does not automatically indicate successful exploitation.

The benign cases in Experiment B were deliberately attack-like and are not representative of ordinary internet traffic.

The available response-time observations include network and backend processing. They cannot be treated as isolated WAF overhead.

## 8. Reproducibility

To repeat the Experiment A validation, obtain the source archive and extract the identified comparison CSV into the analysis folder as `source_comparison.csv`.

Check the source file's checksum using:

```bash
shasum -a 256 source_comparison.csv
```

Run the validator:

```bash
python3 validate_waf_evidence.py source_comparison.csv
```

Run the aggregate analysis separately:

```bash
python3 analyze_waf_results.py
```

Compare the outputs with `validation_results.txt` and `waf_comparison.csv`.

The original comparison CSV and deliberately modified test data are excluded from the public GitHub package.

## 9. Future Improvements

The validation workflow could be extended to check each classification against WAF and backend logs, reconcile the latest controlled-testing data, and automatically produce a discrepancy report.

Further evidence from other group members should be reviewed separately before being included in the final research results.
