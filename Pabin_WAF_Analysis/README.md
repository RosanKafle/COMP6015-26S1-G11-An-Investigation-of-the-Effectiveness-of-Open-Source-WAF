# WAF Results Analysis and Validation

**Student:** Pabin Gurung  
**Student ID:** 22343460  
**Course:** COMP6016 Computer Science Project 2  
**Group:** 11  
**Role:** Measurement, Analysis and Documentation Lead  
**Project:** An Investigation of the Effectiveness of Open-Source Web Application Firewalls

## 1. Project Overview

This folder contains my results analysis, evidence validation and documentation work for the investigation of open-source web application firewalls.

The main activities are calculating evaluation metrics, checking reported classification results, analysing missed detections, comparing transformed attack requests and documenting evidence limitations.

The work considers ModSecurity, NAXSI and Coraza. Experiment A and Experiment B are treated separately because they use different datasets and test arrangements.

## 2. Files and Their Purpose

| File | Purpose |
|---|---|
| `analyze_waf_results.py` | Calculates detection metrics from reported aggregate data and generates a CSV and chart. |
| `validate_waf_evidence.py` | Validates reviewed Experiment A classification records against expected totals. |
| `analyze_naxsi_misses.py` | Analyses NAXSI false negatives by attack category and transformation variant. |
| `reported_aggregates.json` | Stores the previously reported Experiment A and B classification counts. |
| `waf_comparison.csv` | Generated comparison of detection metrics. |
| `waf_detection_chart.png` | Generated chart of WAF detection results. |
| `validation_results.txt` | Saved successful Experiment A validation output. |
| `naxsi_misses_results.txt` | Saved successful NAXSI missed-detection analysis output. |
| `DATA_VALIDATION.md` | Documents evidence provenance, checks, software tests and limitations. |
| `TRANSFORMATION_AND_PERFORMANCE_REVIEW.md` | Reviews additional transformation evidence and clarifies classification versus system performance. |
| `reviewed_group_evidence/` | Contains three supporting CSVs supplied through the group's preserved technical archive. |
| `requirements.txt` | Lists the Python library dependency for the analysis chart. |
| `.gitignore` | Excludes temporary files and the locally retained request-level source CSV. |

## 3. Development Environment

The programs were executed on macOS using Python 3.13.7.

Python's built-in CSV, JSON and collection-processing functionality was used for analysis. Matplotlib was used to generate the chart.

The original WAF testing was conducted by project team members in a controlled laboratory environment. These analysis programs do not launch attacks or configure WAF services.

## 4. Running the Programs

Open Terminal in the `Pabin_WAF_Analysis` directory.

Install the chart dependency if required:

```bash
python3 -m pip install -r requirements.txt
```

Generate the aggregate results comparison:

```bash
python3 analyze_waf_results.py
```

This generates `waf_comparison.csv` and `waf_detection_chart.png`.

To validate Experiment A request classifications, obtain the group's reviewed comparison CSV and save it locally as `source_comparison.csv`.

Run:

```bash
python3 validate_waf_evidence.py source_comparison.csv
```

To analyse NAXSI missed detections, run:

```bash
python3 analyze_naxsi_misses.py
```

Both request-level programs require the separately retained `source_comparison.csv`, which is excluded from this folder's Git history.

The three supporting CSVs used for the additional transformation review are provided in `reviewed_group_evidence/`.

## 5. Evaluation Metrics

The analysis uses the following classification outcomes:

- True positive (TP): malicious-labelled request blocked.
- False negative (FN): malicious-labelled request allowed.
- False positive (FP): benign-labelled request blocked.
- True negative (TN): benign-labelled request allowed.

The evaluation metrics are:

- Recall = TP / (TP + FN) × 100
- Precision = TP / (TP + FP) × 100
- False-positive rate = FP / (FP + TN) × 100
- Accuracy = (TP + TN) / (TP + TN + FP + FN) × 100

Metrics are calculated separately for each WAF and experiment.

## 6. Experiment A Classification Validation

The reviewed Experiment A comparison dataset contains 1,684 request records, comprising 1,564 malicious-labelled requests and 120 benign-labelled requests.

The `validate_waf_evidence.py` program checks required columns, test identifiers, duplicates, classification values and reported confusion-matrix counts.

| Classification | ModSecurity | NAXSI |
|---|---:|---:|
| TP | 1,564 | 1,310 |
| FN | 0 | 254 |
| FP | 11 | 12 |
| TN | 109 | 108 |

The recorded classifications matched all eight expected counts.

The validator reported `VALIDATION PASSED`.

## 7. NAXSI Missed-Detection Analysis

The `analyze_naxsi_misses.py` program identified 254 NAXSI false negatives in Experiment A.

| Attack category | False negatives |
|---|---:|
| XSS | 120 |
| SQL injection | 92 |
| Path traversal | 42 |
| **Total** | **254** |

The transformation breakdown was:

| Variant | False negatives |
|---|---:|
| Baseline | 42 |
| Double encoding | 212 |
| **Total** | **254** |

These counts matched the group's reviewed summary evidence.

An allowed malicious-labelled request is a classification false negative; it does not necessarily establish successful exploitation.

## 8. Additional Transformation Review

The additional CSV evidence supplied by Bishal Giri was examined to compare ModSecurity and NAXSI detection of transformed malicious requests.

The most substantial difference concerned double encoding.

| Double-encoded category | ModSecurity detected | NAXSI detected | NAXSI missed |
|---|---:|---:|---:|
| SQL injection | 120/120 | 28/120 | 92 |
| XSS | 120/120 | 0/120 | 120 |
| **Total** | **240/240** | **28/240** | **212** |

The observed detection rates were 100% for ModSecurity and 11.67% for NAXSI within this particular subset.

A detailed review of the transformations and evidence limitations is provided in `TRANSFORMATION_AND_PERFORMANCE_REVIEW.md`.

## 9. Classification Performance and Latency Limitations

The supplied `performance_metrics.csv` includes precision, recall, F1-score, specificity, false-positive rate, false-negative rate and accuracy.

Although its filename includes the word performance, this file contains classification metrics rather than response-time or resource-utilisation measurements.

It cannot independently support conclusions about WAF processing overhead or throughput.

Earlier response-time results are client-observed end-to-end measurements and should not be presented as isolated WAF latency overhead.

## 10. Software Testing

The aggregate-analysis script was tested with a temporary negative true-positive count. It rejected the invalid input.

The request-level validator was tested with a separate dataset containing a duplicate test identifier. It rejected the modified file with:

`ValueError: Duplicate test IDs found`

The original request-level source file was not modified.

All three analysis programs were also syntax-checked and executed successfully before the initial GitHub commit.

## 11. Data Management and Reproducibility

The reviewed Experiment A comparison CSV was extracted from the group's preserved technical archive.

The original source file is retained separately and excluded from this contribution's Git history. Its archive location and SHA-256 checksum are documented in `DATA_VALIDATION.md`.

The three supporting summary CSVs are included in `reviewed_group_evidence/` for transparency and review.

The classification validation checks agreement between preserved reviewed labels and reported totals. It does not independently adjudicate every original WAF decision against raw logs.

Experiment B is maintained separately. Its aggregate results have not been independently reconciled against the latest full request-level evidence.

## 12. Individual Contribution

My individual contribution includes writing and running the analysis and validation scripts, calculating evaluation metrics, verifying reviewed request classifications, analysing false negatives, generating comparison outputs and documenting additional group evidence.

The original attack execution, WAF configuration and production of the supporting group test records were carried out by other team members.

This distinction is maintained to ensure that the individual contribution accurately represents the work performed.

## 13. Future Work

Further improvements could include checking individual classification records against original WAF and Apache logs, validating additional Experiment B data, and extending the analysis to controlled latency and resource-utilisation measurements.

Any additional datasets should be reviewed independently before inclusion in the final project comparison.

The final report should incorporate the verified transformation findings while clearly describing their scope, denominators and limitations.
