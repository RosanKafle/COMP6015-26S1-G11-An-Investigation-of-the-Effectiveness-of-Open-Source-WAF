# Transformation and Classification Performance Review

**Student:** Pabin Gurung  
**Student ID:** 22343460  
**Course:** COMP6016 Computer Science Project 2  
**Group:** 11  
**Role:** Measurement, Analysis and Documentation Lead  
**Project:** An Investigation of the Effectiveness of Open-Source Web Application Firewalls

## 1. Purpose

This review extends my individual results-analysis work by examining additional Experiment A evidence supplied by Bishal Giri.

The purpose is to verify reported transformation-related detection outcomes, assess false negatives and clarify which performance conclusions are supported by the available data.

The original WAF testing and source result files were produced by the group. My contribution here is the review, comparison, interpretation and documentation of those results.

## 2. Evidence Reviewed

The following files were extracted from the group's preserved technical archive:

| File | Content |
|---|---|
| `transformation_detection_detail.csv` | Detection counts by transformation, attack category and WAF |
| `naxsi_fn_by_transformation.csv` | NAXSI false negatives by transformation |
| `performance_metrics.csv` | Classification evaluation metrics for ModSecurity and NAXSI |

The files are preserved under `reviewed_group_evidence/`.

The original archive is `COMP6016_Group11_BishalGiri_Complete_Code_Data.zip`, under `Final_Submission_Complete/Final_Analysis/Results/`.

These are Experiment A supporting files. They must not be combined with the separate Experiment B dataset.

## 3. Experiment A Overall Classification Results

The reviewed Experiment A dataset contains 1,684 request records per WAF, consisting of 1,564 malicious-labelled requests and 120 benign-labelled requests.

| Classification | ModSecurity | NAXSI |
|---|---:|---:|
| True positives | 1,564 | 1,310 |
| False negatives | 0 | 254 |
| False positives | 11 | 12 |
| True negatives | 109 | 108 |

The results were previously checked using my `validate_waf_evidence.py` program against the reviewed request-level comparison CSV.

The additional `performance_metrics.csv` is consistent with these counts.

| Metric | ModSecurity | NAXSI |
|---|---:|---:|
| Recall | 100.00% | 83.76% |
| Precision | 99.30% | 99.09% |
| False-positive rate | 9.17% | 10.00% |
| Accuracy | 99.35% | 84.20% |
| F1-score | 99.65% | 90.78% |

These values measure classification effectiveness within the tested corpus. They do not by themselves establish effectiveness against all possible attacks or production workloads.

## 4. Transformation-Based Detection Review

The transformation detail CSV provides the following malicious-request detection rates.

| Transformation | ModSecurity | NAXSI |
|---|---:|---:|
| Baseline | 100.00% | 91.25% |
| Case changes | 100.00% | 100.00% |
| Comments | 100.00% | 100.00% |
| Double encoding | 100.00% | 11.67% |
| Encoding | 100.00% | 100.00% |
| Separators | 100.00% | 100.00% |
| URL encoding | 100.00% | 100.00% |
| Whitespace | 100.00% | 100.00% |

The rates describe detection of the tested malicious-labelled requests in each transformation group. The group sizes differ, so the percentages must be interpreted alongside their denominators.

The most substantial difference was observed for double encoding.

## 5. Double-Encoding Results

The double-encoded subset contained 240 malicious-labelled requests for each WAF.

| Attack category | ModSecurity TP | ModSecurity FN | NAXSI TP | NAXSI FN |
|---|---:|---:|---:|---:|
| SQL injection | 120 | 0 | 28 | 92 |
| XSS | 120 | 0 | 0 | 120 |
| **Total** | **240** | **0** | **28** | **212** |

ModSecurity blocked 240 of 240 requests, giving a 100% detection rate for this subset.

NAXSI blocked 28 of 240, giving a detection rate of 11.67%. It allowed the other 212 malicious-labelled requests.

This finding indicates a substantial detection weakness for the tested double-encoded payloads under the evaluated NAXSI configuration.

However, a false negative means that a malicious-labelled request was not blocked. It does not independently establish successful exploitation of the backend application.

## 6. NAXSI False-Negative Distribution

The `naxsi_fn_by_transformation.csv` file reports:

| Transformation | False negatives |
|---|---:|
| Baseline | 42 |
| Double encoding | 212 |
| **Total** | **254** |

This matches the output of my `analyze_naxsi_misses.py` program.

The request-level analysis also identified the following category breakdown:

| Attack category | False negatives |
|---|---:|
| XSS | 120 |
| SQL injection | 92 |
| Path traversal | 42 |
| **Total** | **254** |

The path-traversal misses occurred in baseline testing, while the SQL injection and XSS misses occurred in double-encoded testing.

Together, these results indicate that NAXSI's observed false negatives were concentrated in particular attack categories and transformations rather than being evenly distributed across the tested corpus.

## 7. Classification Performance Versus System Performance

The supplied `performance_metrics.csv` contains precision, recall, F1-score, specificity, false-positive rate, false-negative rate and accuracy.

Despite the filename, it does not contain measurements of response latency, CPU utilisation, memory consumption, throughput or WAF processing overhead.

Therefore, this CSV supports classification-performance analysis, not system-speed comparisons.

Earlier project evidence includes client-observed response-time measurements. Such measurements represent end-to-end behaviour and do not isolate the processing overhead added by a WAF.

A defensible evaluation of WAF overhead would require appropriately controlled baseline and WAF-enabled timing measurements, with comparable workloads and sufficient repeated samples.

No additional latency-overhead claim is made from the three CSVs examined in this review.

## 8. Evidence Consistency and Limitations

The reviewed files agree with the existing Experiment A confusion-matrix totals and NAXSI missed-detection counts.

The original files were generated by another group member. My individual review checks numerical consistency and interprets the reported results; it is not a complete independent replay of the original attacks.

The analysis is limited by the selected attack corpus, configuration, classification labels and available preserved evidence.

Further limitations include:

- False-negative labels do not independently confirm backend exploitation.
- Detection rates for transformation groups with different sample sizes should not be compared without considering their denominators.
- The classification metrics do not establish actual WAF latency overhead.
- Experiment A and Experiment B are separate evaluations and should not be pooled.
- Raw server and WAF logs would be required for comprehensive independent verification of each original decision.

## 9. Individual Contribution and Outcome

My contribution to this review involved examining the preserved CSV files, reconciling their reported detection counts with my existing Python validation outputs and documenting the relevant findings and limitations.

The review confirmed that NAXSI's 254 false negatives consisted of 42 baseline path-traversal requests and 212 double-encoded SQL injection and XSS requests.

It also clarified that the supplied classification-performance file cannot support conclusions about WAF latency or resource overhead.

The resulting documentation strengthens the traceability and interpretation of the project's Experiment A findings while keeping my analysis responsibilities separate from the original attack-testing work.

## 10. Recommended Next Work

The final report should incorporate the verified transformation comparison and explicitly distinguish classification effectiveness from system performance.

If further raw timing or Experiment B records become available, they should be reviewed as separate datasets before additional conclusions are made.

The group handover should retain the original evidence archive, scripts and logs necessary to reproduce or inspect the underlying test results.
