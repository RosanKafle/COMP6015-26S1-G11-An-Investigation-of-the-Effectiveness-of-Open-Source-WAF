# Data Validation and Evidence Management

**Student:** Pabin Gurung  
**Student ID:** 22343460  
**Course:** COMP6016 Computer Science Project 2  
**Group:** 11  
**Role:** Measurement, Analysis and Documentation Lead  
**Project:** An Investigation of the Effectiveness of Open-Source Web Application Firewalls

## 1. Purpose

This document records the data sources, validation procedures, consistency checks, software testing and evidence management associated with my individual WAF analysis contribution.

The main objective is to maintain traceability between the group's experimental results and the numerical findings used in the project report.

The analysis covers reviewed Experiment A records, previously reported Experiment B aggregates, supplementary transformation evidence, and the R11, R12 and automated testing evidence available in the group's integration branch.

Different experiments have different request counts, attack cases and verification procedures. Their results are documented separately to prevent inappropriate comparisons.

The original WAF configuration, laboratory attack execution and collection of technical evidence were performed by other team members. My work concerns analysis, verification of available summaries and documentation.

## 2. Source Data and Provenance

The main independently processed request-level source is the reviewed Experiment A comparison CSV supplied through Bishal Giri's preserved technical archive.

**Archive:** `COMP6016_Group11_BishalGiri_Complete_Code_Data.zip`

**Internal archive path:**

`Final_Submission_Complete/Project/Week_06/results/processed/comparison.csv`

**Local filename:** `source_comparison.csv`

**Recorded SHA-256 checksum:**

`20154dff8b3c20580e0b94bc208d68b89dd8d34983d4e611580b308bbda021c2`

The CSV contains 1,684 request records.

Its expected columns are:

`test_id,category,variant,modsecurity_action,naxsi_action,modsecurity_classification,naxsi_classification`

The reviewed source file is maintained separately from the scripts and is excluded from the individual Git history.

Reproducing the request-level validation requires obtaining this file from the preserved group archive.

## 3. Supporting Experiment A Files

Three additional summary files were reviewed:

| File | Purpose |
|---|---|
| `transformation_detection_detail.csv` | Detection counts organised by transformation, category and WAF. |
| `naxsi_fn_by_transformation.csv` | NAXSI false negatives grouped by transformation. |
| `performance_metrics.csv` | Classification metrics calculated from reported confusion-matrix totals. |

The original files were supplied under:

`Final_Submission_Complete/Final_Analysis/Results/`

Copies are retained in:

`Pabin_WAF_Analysis/reviewed_group_evidence/`

These files relate to Experiment A. They are not substitutes for Sadaiba's R11/R12 request logs or the automated evaluation evidence.

## 4. Experiment A Request-Level Validation

The Python program `validate_waf_evidence.py` checks the reviewed comparison CSV.

The checks include required columns, test identifiers, duplicate identifiers, recognised classifications, record totals and comparison against the expected confusion-matrix counts.

The reviewed dataset contains:

- 1,564 malicious-labelled request records.
- 120 benign-labelled request records.
- 1,684 total records per WAF.

### Classification counts

| Classification | ModSecurity | NAXSI |
|---|---:|---:|
| True positives | 1,564 | 1,310 |
| False negatives | 0 | 254 |
| False positives | 11 | 12 |
| True negatives | 109 | 108 |
| **Total** | **1,684** | **1,684** |

The validation program confirmed that all eight classification totals matched the expected counts.

The recorded program output was:

`VALIDATION PASSED`

The corresponding output is preserved in `validation_results.txt`.

This is a validation of numerical agreement with the reviewed labels. It is not a complete independent reconstruction of each original WAF decision from Apache and WAF logs.

## 5. Classification Metric Verification

The analysis uses the following definitions:

- True positive: malicious-labelled request blocked.
- False negative: malicious-labelled request allowed.
- False positive: benign-labelled request blocked.
- True negative: benign-labelled request allowed.

The calculations are:

- Recall = TP / (TP + FN) × 100.
- Precision = TP / (TP + FP) × 100.
- False-positive rate = FP / (FP + TN) × 100.
- Accuracy = (TP + TN) / (TP + TN + FP + FN) × 100.
- F1-score = 2 × Precision × Recall / (Precision + Recall).

### Experiment A metrics

| Metric | ModSecurity | NAXSI |
|---|---:|---:|
| Recall | 100.00% | 83.76% |
| Precision | 99.30% | 99.09% |
| False-positive rate | 9.17% | 10.00% |
| False-negative rate | 0.00% | 16.24% |
| Specificity | 90.83% | 90.00% |
| Accuracy | 99.35% | 84.20% |
| F1-score | 99.65% | 90.78% |

These values agree with the reported Experiment A confusion-matrix counts, subject to rounding.

They measure classification effectiveness for the reviewed dataset rather than universal WAF detection effectiveness.

## 6. NAXSI False-Negative Analysis

The program `analyze_naxsi_misses.py` processes request-level Experiment A records labelled as NAXSI false negatives.

The analysis identified 254 missed detections.

### By attack category

| Category | False negatives |
|---|---:|
| XSS | 120 |
| SQL injection | 92 |
| Path traversal | 42 |
| **Total** | **254** |

### By transformation

| Transformation | False negatives |
|---|---:|
| Baseline | 42 |
| Double encoding | 212 |
| **Total** | **254** |

The generated analysis output is preserved in `naxsi_misses_results.txt`.

These counts reconcile with the supporting `naxsi_fn_by_transformation.csv`.

The term false negative refers to a classification outcome. It does not independently establish that the allowed request successfully exploited the target application.

## 7. Double-Encoding Evidence Review

The supporting transformation data reports 240 double-encoded malicious-labelled requests per WAF.

| Category | ModSecurity blocked | NAXSI blocked | NAXSI missed |
|---|---:|---:|---:|
| SQL injection | 120 | 28 | 92 |
| XSS | 120 | 0 | 120 |
| **Total** | **240** | **28** | **212** |

ModSecurity's detection rate for this subset was 100%.

NAXSI's detection rate was 11.67%.

The 212 NAXSI missed detections reconcile with the double-encoding false-negative total identified by the request-level script.

This provides additional numerical consistency between the reviewed source records and the supporting group summary.

It does not establish that every missed request achieved its intended application effect.

## 8. Experiment B Aggregate Data

The `reported_aggregates.json` file includes a separate Experiment B containing previously reported classification totals for ModSecurity, Coraza and NAXSI.

The reported Experiment B dataset contains 111 requests per WAF.

The program `analyze_waf_results.py` uses these aggregates to calculate classification metrics and generate comparison outputs.

The original Experiment B aggregate figures have not been independently reconciled against the latest complete request-level evidence.

Accordingly, Experiment B is labelled as reported aggregate evidence.

The 111-request Experiment B dataset must not be treated as equivalent to R11's 225 protected observations or R12's 81 protected observations.

Their different denominators and test eligibility rules prevent automatic pooling.

## 9. R11 Evidence Review

The team's R11 continuity record describes 225 protected observations across ModSecurity, Coraza and NAXSI.

The dataset includes 189 attack observations and 36 original benign-control observations.

Each WAF received 63 attack observations and 12 benign-control observations.

### Reported R11 classification outcomes

| WAF | Attack observations blocked | Benign observations incorrectly blocked |
|---|---:|---:|
| ModSecurity | 63/63 | 0/12 |
| Coraza | 63/63 | 0/12 |
| NAXSI | 60/63 | 3/12 |

The three NAXSI missed attack observations concern repeated testing of the newline separator command injection case `R11-CMD-E03`.

Three additional double-encoded candidate attacks were excluded from the eligible attack count because their intended application effects were not established during baseline testing.

This baseline exclusion is a necessary part of interpreting the R11 result.

**Validation status:** These values are reviewed from the group's R11 continuity documentation. They have not been independently replayed or fully reconstructed from every raw request and server log by my individual scripts.

## 10. R12 Evidence Review

R12 examined command injection separator and encoding variants under an authenticated DVWA laboratory configuration.

The valid protected phase included eight eligible attack cases and one benign control.

Each case was executed three times against three WAFs, resulting in 81 protected observations.

### Reported R12 attack outcomes

| WAF | Attack observations blocked | Attack observations allowed |
|---|---:|---:|
| ModSecurity | 24/24 | 0 |
| Coraza | 24/24 | 0 |
| NAXSI | 18/24 | 6 |

NAXSI allowed the newline separator variants `R12-CMD-NL-PCT` and `R12-CMD-NL-PLUS`, each repeated three times.

The team's R12 record describes confirmation using observed command effects, correlated access logs and WAF blocking records.

Five earlier baseline runs were invalidated because the runner lacked the required authenticated application session. These invalid runs were excluded from the final eligible set.

The team's evidence reports that the R12 benign control was allowed by all three WAFs.

**Validation status:** My contribution is review and interpretation of the documented R12 findings. My Python programs do not independently replay the command injection cases or corroborate each raw log entry.

## 11. Expanded R11 Benign Controls

A separate follow-up examined four additional benign cases selected because they contained attack-like text.

Each case was repeated three times per WAF.

| WAF | Additional benign observations blocked | Additional benign observations allowed |
|---|---:|---:|
| ModSecurity | 0/12 | 12 |
| Coraza | 0/12 | 12 |
| NAXSI | 12/12 | 0 |

The evaluated NAXSI configuration blocked all 12 additional benign observations.

This is a relevant indication of false-positive behaviour for these selected examples.

However, four purposely chosen cases are insufficient for estimating the false-positive rate across normal application traffic.

These additional controls are reported separately from the original R11 benign set.

## 12. Earlier Automated Evaluation

The integrated repository contains automated baseline, ModSecurity and Coraza evaluation outputs.

Relevant files include:

`analysis/final/report_summary.md`

`analysis/final/confusion_matrices.csv`

These results are distinct from Experiment A, Experiment B, R11 and R12.

The confusion-matrix summary contains differences between its reported attack row counts and the sum of true positives and false negatives.

For example, the ModSecurity attack-only row records 465 attack rows but 162 true positives and 282 false negatives.

The classification counts total 444, leaving a difference of 21 rows.

The exact treatment of these records requires further review against the classification rules and underlying outputs.

It would be inappropriate to assume that all 21 were exclusions, failed attacks or classification errors without confirming the relevant processing logic.

The corresponding automated classification rates remain reported results pending reconciliation.

## 13. Performance Evidence

There are two distinct meanings of performance in the group evidence.

First, `performance_metrics.csv` contains classification statistics. It does not measure WAF processing time or computer resource consumption.

Second, the automated evaluation contains client-observed end-to-end response-time summaries.

| Environment | Attack-only mean latency | Mixed traffic mean latency |
|---|---:|---:|
| Baseline without WAF | 6.196 ms | 6.220 ms |
| ModSecurity | 7.946 ms | 9.925 ms |
| Coraza | 9.022 ms | 16.686 ms |

These values originate from the automated evaluation summary.

They are observations from recorded client requests rather than measurements of isolated WAF processing overhead.

They should not be used to claim a universal latency penalty or to compare NAXSI against the other WAFs without equivalent measurements.

## 14. Software Testing and Error Handling

The three Python analysis programs were previously syntax-checked and executed successfully.

The aggregate analysis program was tested with a temporary negative true-positive value and rejected the invalid input.

The request-level validation program was tested with a temporary CSV containing a duplicate test identifier.

The program rejected that input with:

`ValueError: Duplicate test IDs found`

The original reviewed source file was not modified during those negative tests.

These checks demonstrate basic software validation and input error handling.

They are not a comprehensive test suite and do not validate the original WAF experiment execution.

## 15. Data Management

The original Experiment A source archive was preserved.

A separate working copy of its reviewed comparison CSV was used for local analysis.

The recorded SHA-256 value identifies the reviewed source data used during validation.

The request-level CSV is excluded from the individual Git history, while the smaller supporting summary files are included for inspection.

R11, R12 and automated test evidence remain referenced through the shared project repository.

Raw technical outputs should be preserved in the group handover where required for reproducibility and supervisor review.

The individual analysis package does not contain production credentials or require testing outside the controlled laboratory environment.

## 16. Reproducibility Instructions

The analysis was developed on macOS using Python 3.13.7 and Matplotlib.

Install required dependencies:

`python3 -m pip install -r requirements.txt`

Generate aggregate metrics and chart:

`python3 analyze_waf_results.py`

Validate Experiment A after providing the reviewed CSV:

`python3 validate_waf_evidence.py source_comparison.csv`

Analyse Experiment A NAXSI misses:

`python3 analyze_naxsi_misses.py`

Review integrated evidence:

`INTEGRATED_WAF_EVIDENCE_ANALYSIS.md`

Reproducing R11, R12 or the earlier automated evaluation requires the corresponding group test environment, scripts, input cases, WAF configurations and preserved logs.

Those experiments are not reproduced by the three individual Role 4 analysis scripts.

## 17. Evidence Verification Summary

| Evidence set | Review status | Important qualification |
|---|---|---|
| Experiment A reviewed comparison CSV | Request-level classification totals validated | Raw server decisions not independently reconstructed |
| Experiment A NAXSI missed detections | Processed using Python and reconciled with summaries | Allowed requests do not automatically prove exploitation |
| Experiment A transformation summaries | Numerical consistency reviewed | Original attacks not independently replayed |
| Experiment B aggregates | Metrics calculated from reported counts | Complete request-level reconciliation pending |
| R11 protected results | Group documentation reviewed | Independent raw evidence audit pending |
| R12 protected results | Group documentation reviewed | Independent raw evidence audit pending |
| Expanded benign results | Group documentation reviewed | Small, deliberately selected corpus |
| Earlier automated results | Summary figures reviewed | Classification denominators require reconciliation |
| Client-observed timing results | Existing summary interpreted | No isolated WAF overhead established |

## 18. Known Issues and Limitations

The main limitations are:

1. The reviewed classification labels depend on the source evidence prepared by the group.
2. Experiment B aggregates have not been fully independently reconciled.
3. R11 and R12 results have not been independently replayed through my analysis programs.
4. Some baseline attack candidates were invalid or did not demonstrate the intended application effect.
5. A false-negative classification does not necessarily indicate successful exploitation.
6. Expanded benign cases do not represent a statistically representative sample of legitimate user activity.
7. The automated confusion-matrix summary contains unresolved denominator differences.
8. The timing summaries do not isolate WAF processing overhead.
9. Different experiments use different corpora, configurations and eligibility rules.
10. The overall integrated evidence audit is pending.

These issues must remain visible in the final report instead of being silently combined into a single set of verified results.

## 19. Outcome and Individual Contribution

My individual validation work confirmed that the reviewed Experiment A request records agreed with the reported ModSecurity and NAXSI confusion-matrix totals.

My NAXSI analysis identified 254 false negatives, including 212 double-encoded SQL injection and XSS requests and 42 baseline path traversal requests.

The supplementary transformation files reconciled with these counts.

I subsequently reviewed the integrated repository's reported R11, R12, expanded benign and automated evaluation findings to support the group's final report preparation.

This review identifies both consistent evidence and outstanding discrepancies requiring additional verification.

My individual contribution consists of analytical scripts, metric calculations, classification checks, evidence interpretation and documentation. The original group attack execution and WAF infrastructure work remain attributable to the relevant testing team members.

## 20. Evidence References

Individual analysis folder:

`Pabin_WAF_Analysis/`

Integrated review:

`Pabin_WAF_Analysis/INTEGRATED_WAF_EVIDENCE_ANALYSIS.md`

Individual branch:

`role4`

Group reference branch:

`comp6016-final-integration`

Important group paths:

- `Bishal/Final_Evidence/Results/`
- `r11_r12_waf_evaluation/WORK_SYNC.md`
- `analysis/final/report_summary.md`
- `analysis/final/confusion_matrices.csv`
- `VALIDATION.md`
- `PROJECT_STATUS.md`

The final project submission should retain the relevant commit identifiers and evidence files so the reported results can be traced to their sources.
