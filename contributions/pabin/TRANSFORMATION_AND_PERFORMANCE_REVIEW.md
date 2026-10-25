# Transformation, Detection and Performance Evidence Review

**Student:** Pabin Gurung  
**Student ID:** 22343460  
**Course:** COMP6016 Computer Science Project 2  
**Group:** 11  
**Role:** Measurement, Analysis and Documentation Lead  
**Project:** An Investigation of the Effectiveness of Open-Source Web Application Firewalls

## 1. Purpose

This document reviews the group's evidence concerning transformed malicious requests, missed detections, false positives and performance measurements.

The original review focused on Experiment A evidence supplied by Bishal Giri. It has been extended to incorporate the documented R11 and R12 findings from Sadaiba Kumar Acharya and the earlier automated evaluation included in the group integration branch.

My individual responsibility is to examine available results, calculate or verify relevant metrics, compare findings and explain their limitations. I did not independently execute every attack or configure the WAFs used in the original experiments.

The experiments are documented separately because they use different test cases, sample sizes, configurations and evidence requirements.

## 2. Evidence Sources

The following files support this review.

| Source | Purpose |
|---|---|
| `reviewed_group_evidence/transformation_detection_detail.csv` | Experiment A detection counts by attack category and transformation |
| `reviewed_group_evidence/naxsi_fn_by_transformation.csv` | Experiment A NAXSI false negatives by transformation |
| `reviewed_group_evidence/performance_metrics.csv` | Experiment A classification metrics |
| `source_comparison.csv` | Locally retained reviewed Experiment A request-level classifications |
| `experiments/r11-r12/WORK_SYNC.md` | Group documentation of R11, R12 and related testing |
| `analysis/final/report_summary.md` | Earlier automated evaluation and timing summaries |
| `analysis/final/confusion_matrices.csv` | Earlier automated classification summary |
| `INTEGRATED_WAF_EVIDENCE_ANALYSIS.md` | My consolidated review of the separate evidence sets |

The original Experiment A files were supplied through `COMP6016_Group11_BishalGiri_Complete_Code_Data.zip`.

The R11, R12 and automated testing evidence is referenced from the group's `comp6016-final-integration` branch.

## 3. Experiment A: Classification Results

The reviewed Experiment A dataset contains 1,684 request records per WAF, including 1,564 malicious-labelled and 120 benign-labelled requests.

| Classification | ModSecurity | NAXSI |
|---|---:|---:|
| True positives | 1,564 | 1,310 |
| False negatives | 0 | 254 |
| False positives | 11 | 12 |
| True negatives | 109 | 108 |

My `validate_waf_evidence.py` program checked the reviewed comparison CSV against these reported counts.

All eight confusion-matrix totals matched.

The program output recorded `VALIDATION PASSED`.

This establishes numerical consistency between the reviewed records and the expected totals. It does not independently verify every original WAF decision using raw application and WAF logs.

### Classification metrics

| Metric | ModSecurity | NAXSI |
|---|---:|---:|
| Recall | 100.00% | 83.76% |
| Precision | 99.30% | 99.09% |
| False-positive rate | 9.17% | 10.00% |
| Accuracy | 99.35% | 84.20% |
| F1-score | 99.65% | 90.78% |

These figures describe the reviewed Experiment A corpus and tested configurations.

They do not represent general detection rates across all applications or attack types.

## 4. Experiment A: Transformation-Based Detection

The transformation summary supplied by Bishal provides the following reported detection percentages.

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

The most substantial difference was observed in the double-encoded requests.

The transformation groups have different request counts, so their percentages should not be interpreted without considering the respective denominators.

A payload transformation changes how attack text is represented in the HTTP request. Whether the request remains effective against the backend application depends on how the application and intervening components interpret it.

## 5. Experiment A: Double-Encoding Findings

The reviewed double-encoded subset contains 240 malicious-labelled requests per WAF.

| Attack category | ModSecurity blocked | NAXSI blocked | NAXSI allowed |
|---|---:|---:|---:|
| SQL injection | 120 | 28 | 92 |
| XSS | 120 | 0 | 120 |
| **Total** | **240** | **28** | **212** |

ModSecurity blocked 240 of 240 requests, giving 100% detection within this subset.

NAXSI blocked 28 of 240 requests, giving 11.67% detection.

The difference suggests a substantial limitation in detection of the selected double-encoded requests under the evaluated NAXSI configuration.

However, an allowed malicious-labelled request is not automatically proof that the application executed the intended exploit.

Where possible, successful attack effects should be established against the application independently of the WAF decision.

## 6. Experiment A: False-Negative Distribution

The `analyze_naxsi_misses.py` program processed the reviewed request-level comparison file and identified 254 NAXSI false negatives.

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

These counts reconcile with the supporting transformation summaries.

The false negatives are concentrated in particular categories and variants rather than distributed evenly across the reviewed corpus.

The 42 baseline misses concern path traversal, while the 212 double-encoded misses concern SQL injection and XSS.

## 7. R11: Validated Attack-Case Observations

The separate R11 evaluation used validated attack cases and repeated protected testing against three WAFs.

The documented protected results contain 225 observations:

- 189 attack observations.
- 36 original benign-control observations.

Each WAF received 63 attack observations and 12 benign-control observations.

### R11 attack blocking

| WAF | Blocked | Allowed |
|---|---:|---:|
| ModSecurity | 63/63 | 0 |
| Coraza | 63/63 | 0 |
| NAXSI | 60/63 | 3 |

The three NAXSI misses occurred during repeated testing of a newline separator command injection case, `R11-CMD-E03`.

The group review associated this behaviour with a gap in the evaluated NAXSI rules.

Three other double-encoded candidates were excluded from the validated attack denominator because their intended effect was not established against the baseline application.

This exclusion prevents ineffective attack candidates from being counted as successful WAF blocks.

The R11 results are reviewed from the group's documentation. They were not independently replayed through my Role 4 analysis programs.

## 8. R12: Command Separator and Encoding Variants

R12 extended testing of command injection separators and request encodings.

The protected phase used eight eligible attack cases and one benign control, repeated three times per WAF.

This produced 81 protected observations across ModSecurity, Coraza and NAXSI.

### R12 attack blocking

| WAF | Blocked | Allowed |
|---|---:|---:|
| ModSecurity | 24/24 | 0 |
| Coraza | 24/24 | 0 |
| NAXSI | 18/24 | 6 |

NAXSI allowed two newline separator variants:

- `R12-CMD-NL-PCT`
- `R12-CMD-NL-PLUS`

Each variant was allowed in three repetitions.

The group's continuity record describes confirmation of the command effect using the returned application response, corresponding access records and WAF log evidence.

The same evaluation did not observe this particular miss for the tested semicolon, logical AND or pipe separator cases.

Five earlier R12 baseline runs were excluded because an unauthenticated session produced redirects rather than the intended application behaviour.

The corrected authenticated run and the excluded invalid attempts must remain distinguishable.

These R12 findings should not be interpreted as a general statement that every NAXSI deployment is vulnerable to command injection.

## 9. Comparison of Experiment A, R11 and R12

The three evidence sets show different weaknesses under different configurations.

| Experiment | Primary observation | Interpretation |
|---|---|---|
| Experiment A | NAXSI allowed 212 of 240 tested double-encoded malicious-labelled requests | Detection weakness for selected transformations |
| R11 | NAXSI allowed 3 of 63 validated attack observations | Repeated miss for one newline separator case |
| R12 | NAXSI allowed 6 of 24 eligible attack observations | Repeated misses for two newline separator variants |

These counts are not directly additive.

Experiment A is based on reviewed classification labels. R11 and R12 used eligibility checks intended to establish an application effect before protected testing.

The request sets, WAF configurations and experimental procedures also differ.

Therefore, a single combined NAXSI detection rate calculated across these experiments would be misleading.

## 10. False Positives and Legitimate Traffic

WAF effectiveness must be evaluated against legitimate requests as well as malicious requests.

A firewall that blocks more requests is not necessarily better if it also blocks valid user activity.

### R11 original benign controls

| WAF | Benign observations blocked | Benign observations allowed |
|---|---:|---:|
| ModSecurity | 0/12 | 12 |
| Coraza | 0/12 | 12 |
| NAXSI | 3/12 | 9 |

### Expanded R11 benign controls

Four additional benign cases containing suspicious-looking text were tested three times per WAF.

| WAF | Benign observations blocked | Benign observations allowed |
|---|---:|---:|
| ModSecurity | 0/12 | 12 |
| Coraza | 0/12 | 12 |
| NAXSI | 12/12 | 0 |

NAXSI incorrectly blocked all 12 additional benign observations in this selected corpus.

The results demonstrate a practical usability concern for the evaluated configuration.

However, these are small, deliberately selected test sets. Their proportions should not be presented as general false-positive rates for ordinary web traffic.

The original and expanded controls are documented separately for traceability.

## 11. Earlier Automated Evaluation

The integrated repository contains an earlier automated evaluation covering baseline traffic, ModSecurity and Coraza.

It includes attack-only and mixed-traffic experiments.

The relevant summaries are:

`analysis/final/report_summary.md`

`analysis/final/confusion_matrices.csv`

The automated evaluation considers multiple categories of web application weaknesses.

Its results are relevant to the wider project because they show that request-based filtering does not necessarily address every application security weakness.

However, this evaluation uses a separate request corpus and classification procedure.

It does not provide a directly comparable NAXSI dataset.

### Classification reconciliation issue

The automated confusion-matrix summary contains some rows where the total number of attack records differs from the number of classified true positives and false negatives.

For example, the ModSecurity attack-only summary reports:

- 465 attack rows.
- 162 true positives.
- 282 false negatives.

The true-positive and false-negative counts total 444, a difference of 21.

The treatment of these records should be checked against the underlying classification script and raw results.

Until this discrepancy is reconciled, the related summary percentages should be identified as reported results rather than independently verified final classification rates.

## 12. Classification Performance Versus System Performance

The group evidence uses the term performance in two different contexts.

**Classification performance** concerns detection effectiveness, including recall, precision, false-positive rate, false-negative rate, accuracy and F1-score.

**System performance** concerns behaviour such as response latency, throughput, CPU usage, memory consumption and stability.

The Experiment A file `performance_metrics.csv` contains classification statistics. It does not measure response times or resource consumption.

The filename alone must not be used as evidence of WAF latency or processing overhead.

## 13. Client-Observed Response Times

The earlier automated evaluation reports the following average client-observed response times.

| Environment | Attack-only average | Mixed-traffic average |
|---|---:|---:|
| Baseline without WAF | 6.196 ms | 6.220 ms |
| ModSecurity | 7.946 ms | 9.925 ms |
| Coraza | 9.022 ms | 16.686 ms |

These values were recorded in the group's `analysis/final/report_summary.md`.

The attack-only and mixed-traffic workloads are separate conditions.

Within their respective recorded runs, both WAF-enabled environments showed higher average client-observed response times than the baseline.

However, these measurements include end-to-end request processing, not only the time spent executing WAF rules.

They may also reflect differences in application behaviour, network communication, test execution and system load.

The observed differences should therefore not be described as precisely isolated WAF processing overhead.

No equivalent NAXSI timing series is present in this automated evaluation.

A robust overhead assessment would require comparable workloads, controlled configurations, repeated measurements and appropriate analysis of variability.

## 14. Evidence Consistency

Several Experiment A results reconcile numerically.

The reviewed confusion matrix records 254 NAXSI false negatives.

The request-level category breakdown also totals 254.

The transformation breakdown consists of 212 double-encoded misses and 42 baseline misses, again totalling 254.

The double-encoded category breakdown consists of 92 SQL injection misses and 120 XSS misses, totalling 212.

These agreements increase confidence in the consistency of the reviewed classification data.

They do not prove that the original test traffic, application behaviour and WAF logging were independently correct.

The R11 and R12 continuity documentation also reports repeated results and application effect verification, but those group records require separate final evidence auditing.

## 15. Limitations

The main limitations of this comparison are:

1. Different experiments use different datasets and eligibility criteria.
2. Original WAF configurations may differ across testing phases.
3. Reviewed classifications do not automatically prove successful exploitation.
4. Some baseline candidates were excluded because their intended application effect was not observed.
5. The R11 and R12 findings have not been independently replayed by my Role 4 scripts.
6. Expanded benign traffic is not representative of all legitimate application requests.
7. Earlier automated classification summaries have unresolved denominator differences.
8. Client-observed timing results do not isolate WAF processing overhead.
9. The automated timing comparison does not include NAXSI under equivalent conditions.
10. The final integrated evidence audit remains pending.

These limitations are important when interpreting the relative strengths and weaknesses of the tested WAFs.

## 16. Individual Contribution

My individual contribution consists of analysing and interpreting the preserved group evidence.

I developed and executed Python programs to calculate classification metrics, validate reviewed Experiment A records and investigate NAXSI false negatives.

I reviewed Bishal's transformation results and checked them against the request-level classifications.

I also examined the documented findings from Sadaiba's R11 and R12 experiments, the expanded benign controls and the earlier automated evaluation.

I documented differences in denominators, evidence validation requirements and performance measurement methods.

The underlying attack execution, WAF deployment and original raw evidence collection remain the work of the relevant group members.

## 17. Conclusions

The reviewed Experiment A results indicate that ModSecurity was more effective than NAXSI against the selected double-encoded malicious-labelled requests under the evaluated configurations.

The independently documented R11 and R12 test sets identified repeated NAXSI misses involving newline separator command injection.

The expanded benign cases further demonstrate that blocking aggressive or suspicious-looking request content may interfere with legitimate application use.

These findings support the importance of evaluating WAFs using both detection effectiveness and false-positive behaviour.

They also show why successful baseline attack validation, preserved logs, consistent denominators and clear experimental separation are necessary for credible research conclusions.

The earlier automated response-time measurements provide useful end-to-end observations, but do not independently establish WAF processing overhead.

The final project report should maintain these distinctions and resolve any outstanding evidence discrepancies before presenting results as fully verified.

## 18. Supporting References

The supporting files and locations are:

- `contributions/pabin/README.md`
- `contributions/pabin/DATA_VALIDATION.md`
- `contributions/pabin/INTEGRATED_WAF_EVIDENCE_ANALYSIS.md`
- `contributions/pabin/reviewed_group_evidence/`
- `contributions/bishal/Final_Evidence/Results/`
- `experiments/r11-r12/WORK_SYNC.md`
- `analysis/final/report_summary.md`
- `analysis/final/confusion_matrices.csv`

The individual analysis is maintained on the `role4` branch, with the group's combined evidence referenced from `comp6016-final-integration`.

The final submission should identify the exact commits used for the evidence review.
