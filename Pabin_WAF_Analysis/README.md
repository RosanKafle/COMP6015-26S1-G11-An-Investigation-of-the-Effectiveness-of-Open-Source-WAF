# WAF Results Analysis, Validation and Integrated Evidence Review

**Student:** Pabin Gurung  
**Student ID:** 22343460  
**Course:** COMP6016 Computer Science Project 2  
**Group:** 11  
**Role:** Measurement, Analysis and Documentation Lead  
**Project:** An Investigation of the Effectiveness of Open-Source Web Application Firewalls

## 1. Overview

This folder contains my individual technical contribution to the group's investigation of open-source web application firewalls.

My work focuses on analysing test results, validating reported classification counts, investigating missed detections, comparing evidence from different experiments and documenting the limitations of the results.

The evaluated WAFs include ModSecurity, NAXSI and Coraza. The original laboratory testing, WAF deployment and attack execution were carried out by other team members.

This folder contains three Python analysis programs, generated comparison outputs, evidence review documents and supporting CSV summaries.

The experiments use different datasets and conditions. Their results must be interpreted separately rather than combined into one overall WAF effectiveness score.

## 2. Files and Folder Structure

| File or folder | Purpose |
|---|---|
| `analyze_waf_results.py` | Calculates classification metrics from reported aggregate results and generates a CSV and chart. |
| `validate_waf_evidence.py` | Checks reviewed Experiment A request records and classification totals. |
| `analyze_naxsi_misses.py` | Analyses Experiment A NAXSI false negatives by attack category and transformation. |
| `reported_aggregates.json` | Stores reported classification totals for Experiments A and B. |
| `waf_comparison.csv` | Generated classification comparison. |
| `waf_detection_chart.png` | Generated detection comparison chart. |
| `validation_results.txt` | Saved successful Experiment A validation results. |
| `naxsi_misses_results.txt` | Saved NAXSI false-negative analysis output. |
| `INTEGRATED_WAF_EVIDENCE_ANALYSIS.md` | Integrated analysis of Bishal's, Sadaiba's and earlier automated group evidence. |
| `DATA_VALIDATION.md` | Documents evidence provenance, validation checks, integrity and limitations. |
| `TRANSFORMATION_AND_PERFORMANCE_REVIEW.md` | Reviews transformation results and classification versus timing measurements. |
| `reviewed_group_evidence/` | Three preserved supporting CSV files from Bishal's Experiment A analysis. |
| `requirements.txt` | Python chart dependency. |
| `.gitignore` | Excludes local request-level source data and temporary files. |

## 3. Development Environment

The analysis was developed and executed using Python 3.13.7 on macOS.

Standard Python libraries were used to read CSV and JSON data, count classifications and calculate metrics. Matplotlib was used to produce the comparison chart.

The analysis programs process existing results. They do not deploy WAF services or execute attacks.

## 4. Reproducing the Analysis

Open Terminal in the `Pabin_WAF_Analysis` folder.

Install the chart dependency if necessary:

```bash
python3 -m pip install -r requirements.txt
```

Generate the aggregate comparison:

```bash
python3 analyze_waf_results.py
```

This generates `waf_comparison.csv` and `waf_detection_chart.png`.

For request-level Experiment A validation, obtain the reviewed comparison CSV from the group's preserved archive and save it in this directory as `source_comparison.csv`.

Run:

```bash
python3 validate_waf_evidence.py source_comparison.csv
```

Analyse NAXSI missed detections:

```bash
python3 analyze_naxsi_misses.py
```

The request-level source CSV is intentionally not committed to this individual folder. The original group archive is required to reproduce those request-level checks.

The three supporting Experiment A summary CSVs are included under `reviewed_group_evidence/`.

The R11, R12 and earlier automated evaluation evidence is referenced in the group's integrated repository rather than copied into this folder.

## 5. Evaluation Metrics

The following classification terms are used:

- **True positive (TP):** Malicious-labelled request blocked.
- **False negative (FN):** Malicious-labelled request allowed.
- **False positive (FP):** Benign-labelled request blocked.
- **True negative (TN):** Benign-labelled request allowed.

The calculated metrics are:

- Recall = TP / (TP + FN) × 100
- Precision = TP / (TP + FP) × 100
- False-positive rate = FP / (FP + TN) × 100
- Accuracy = (TP + TN) / (TP + TN + FP + FN) × 100

The program calculates metrics for the reported aggregate datasets. The validity of an aggregate depends on the quality and completeness of its underlying classifications.

## 6. Experiment A: Validated Classification Counts

Bishal's reviewed Experiment A comparison data contains 1,684 request records per WAF, with 1,564 malicious-labelled records and 120 benign-labelled records.

| Classification | ModSecurity | NAXSI |
|---|---:|---:|
| TP | 1,564 | 1,310 |
| FN | 0 | 254 |
| FP | 11 | 12 |
| TN | 109 | 108 |

The `validate_waf_evidence.py` program checked the reviewed source CSV against the expected classification counts.

All eight expected counts matched, and the saved program output recorded `VALIDATION PASSED`.

This confirms numerical consistency with the reviewed classifications. It does not independently verify every original request against server logs.

## 7. Experiment A: Missed Detections

The `analyze_naxsi_misses.py` program identified 254 NAXSI false negatives.

| Attack category | Missed detections |
|---|---:|
| XSS | 120 |
| SQL injection | 92 |
| Path traversal | 42 |
| **Total** | **254** |

By transformation:

| Transformation | Missed detections |
|---|---:|
| Baseline | 42 |
| Double encoding | 212 |
| **Total** | **254** |

The examined double-encoded subset contained 240 malicious-labelled requests per WAF.

ModSecurity blocked all 240, while NAXSI blocked 28 and allowed 212.

These results describe detection of the tested requests under the evaluated configurations. An allowed malicious-labelled request does not automatically establish successful backend exploitation.

## 8. Experiment B: Reported Aggregate Comparison

The `reported_aggregates.json` file also contains the previously reported Experiment B results for ModSecurity, Coraza and NAXSI.

Experiment B is maintained separately from Experiment A because its corpus and test conditions differ.

The existing aggregate comparison program can calculate metrics from those reported results, but Experiment B has not been independently reconciled against the latest complete request-level evidence.

Its figures should therefore be described as reported aggregates rather than fully validated request-level results.

Experiment B must also remain distinct from Sadaiba's R11 and R12 protected test observations.

## 9. Integrated Review: Sadaiba's R11 and R12

The document `INTEGRATED_WAF_EVIDENCE_ANALYSIS.md` extends my analysis to additional testing evidence included in the group's `comp6016-final-integration` branch.

### R11 protected observations

The R11 evidence records 225 protected observations across three WAFs, including 189 attack observations and 36 original benign-control observations.

Each WAF received 63 validated attack observations and 12 benign observations.

| WAF | Attacks blocked | Original benign requests blocked |
|---|---:|---:|
| ModSecurity | 63/63 | 0/12 |
| Coraza | 63/63 | 0/12 |
| NAXSI | 60/63 | 3/12 |

NAXSI missed three repetitions of one newline separator command injection case.

Three additional double-encoded attack candidates were excluded from the effective attack denominator because their baseline application effect was not established.

### R12 protected observations

R12 examined command separator variants using authenticated laboratory testing.

The protected phase recorded 81 observations across three WAFs.

| WAF | Eligible attack observations blocked |
|---|---:|
| ModSecurity | 24/24 |
| Coraza | 24/24 |
| NAXSI | 18/24 |

NAXSI missed two newline separator variants, each repeated three times.

The group evidence records application effect confirmation and correlated logs for the six missed observations.

Five earlier R12 baseline runs were invalid because the required authenticated session was not established. They are excluded from the valid results.

### Expanded benign testing

Four additional, deliberately selected benign cases were repeated three times per WAF.

| WAF | Additional benign requests incorrectly blocked |
|---|---:|
| ModSecurity | 0/12 |
| Coraza | 0/12 |
| NAXSI | 12/12 |

These findings describe the tested cases and WAF configurations. The small, purposively selected corpus does not support a general population false-positive estimate.

## 10. Earlier Automated ModSecurity and Coraza Results

The integrated repository also contains earlier automated attack-only and mixed-traffic evaluation results.

Relevant files include:

- `analysis/final/report_summary.md`
- `analysis/final/confusion_matrices.csv`

These data describe a separate experimental corpus and must not be pooled with Experiment A, Experiment B or R11/R12.

The confusion matrix summary contains some differences between total attack rows and the sum of true positives and false negatives.

Those differences require reconciliation before the corresponding classification rates can be treated as final independently checked results.

The automated timing evidence includes baseline, ModSecurity and Coraza measurements. It does not provide equivalent NAXSI timing rows for that same evaluation.

## 11. Classification Metrics Versus System Performance

The Experiment A file `performance_metrics.csv` contains classification statistics such as precision, recall, specificity, F1-score and accuracy.

It does not measure CPU usage, memory consumption, throughput or response latency.

The earlier automated group evaluation includes client-observed end-to-end response times.

These timing measurements should not be described as isolated WAF processing overhead because other system and workload effects may contribute.

Detection effectiveness and system performance are therefore documented separately.

## 12. Software Validation

The analysis scripts were syntax-checked and successfully executed.

The aggregate-analysis program rejected a deliberately invalid negative true-positive count.

The request-level validator also rejected a temporary CSV containing a duplicate test identifier, reporting:

`ValueError: Duplicate test IDs found`

The original reviewed source file was preserved separately.

Successful Experiment A validation and NAXSI missed-detection outputs are retained as text files.

These checks demonstrate working analysis and selected input validation. They do not constitute independent re-execution of the original WAF attacks.

## 13. Data Provenance and Integrity

The Experiment A request-level CSV was obtained from Bishal's preserved group archive:

`COMP6016_Group11_BishalGiri_Complete_Code_Data.zip`

Internal archive location:

`Final_Submission_Complete/Project/Week_06/results/processed/comparison.csv`

Recorded SHA-256:

`20154dff8b3c20580e0b94bc208d68b89dd8d34983d4e611580b308bbda021c2`

The request-level file remains excluded from this individual Git history.

Three supporting CSV summaries are included under `reviewed_group_evidence/`.

The R11, R12 and earlier automated results are documented through the shared integration branch, rather than being presented as newly collected individual experiments.

## 14. Individual Contribution

As the Measurement, Analysis and Documentation Lead, my technical contribution includes:

1. Developing and running three Python programs for classification analysis, evidence validation and false-negative analysis.
2. Preparing the aggregate comparison CSV and visual chart.
3. Checking reviewed Experiment A request classifications against reported totals.
4. Analysing NAXSI misses by category and transformation.
5. Reviewing supplementary transformation and classification evidence supplied by Bishal.
6. Reviewing the reported R11, R12, expanded benign and automated evaluation findings from the integrated repository.
7. Documenting data provenance, test limitations, evidence discrepancies and reproducibility requirements.

I did not personally perform all the original attacks, configure all WAFs or generate the raw group testing evidence.

The distinction between my analytical contribution and the team's testing contribution is maintained throughout this documentation.

## 15. Known Limitations

The main limitations are:

- Experiment A validation checks consistency with reviewed labels, not every underlying raw server record.
- Experiment B aggregate results still require independent request-level reconciliation.
- R11 and R12 results apply to their selected eligible cases and configurations.
- Some baseline candidates were excluded because the intended attack effect was not established.
- The expanded benign corpus was small and deliberately selected.
- Earlier automated confusion matrix discrepancies remain unresolved in this review.
- Classification results cannot independently establish successful exploitation or WAF latency overhead.
- Different experimental corpora must not be combined into a single effectiveness percentage.
- The group's integrated evidence audit remains pending.

## 16. Repository References and Handover

Individual analysis location:

`Pabin_WAF_Analysis/`

Individual working branch:

`role4`

Group integration reference branch:

`comp6016-final-integration`

Primary integrated review:

`INTEGRATED_WAF_EVIDENCE_ANALYSIS.md`

Relevant shared evidence:

- `Bishal/Final_Evidence/Results/`
- `r11_r12_waf_evaluation/WORK_SYNC.md`
- `analysis/final/report_summary.md`
- `analysis/final/confusion_matrices.csv`

The individual technical ZIP contains the committed analysis folder and outputs. It does not replace the complete group evidence handover.

For final submission, the exact Git commit and any remaining validation limitations should be recorded alongside the supporting source files.
