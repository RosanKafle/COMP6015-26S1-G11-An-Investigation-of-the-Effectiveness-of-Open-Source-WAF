# Integrated WAF Evidence Analysis

**Student:** Pabin Gurung  
**Student ID:** 22343460  
**Course:** COMP6016 Computer Science Project 2  
**Group:** 11  
**Role:** Measurement, Analysis and Documentation Lead  
**Project:** An Investigation of the Effectiveness of Open-Source Web Application Firewalls

## 1. Purpose

This document brings together the relevant testing evidence produced by Bishal Giri, Sadaiba Kumar Acharya and other project team members.

As the Measurement, Analysis and Documentation Lead, my responsibility is to examine the available results, compare WAF behaviour, check numerical consistency and document findings that can be supported by the preserved evidence.

The original experiments were conducted by the team's testing and infrastructure members. My contribution is the independent review of reported classification results, calculation of evaluation metrics and interpretation of the evidence.

The project evaluates three open-source web application firewalls: ModSecurity, NAXSI and Coraza. Testing was conducted against deliberately vulnerable applications in a controlled laboratory environment.

The evidence consists of several experiments that used different request sets and verification procedures. Their results are presented separately to avoid misleading comparisons.

## 2. Evidence Sources and Verification

The integrated project repository is available at:

`https://github.com/RosanKafle/COMP6015-26S1-G11-An-Investigation-of-the-Effectiveness-of-Open-Source-WAF`

The reference branch is `comp6016-final-integration`.

The evidence examined includes:

| Source | Main evidence |
|---|---|
| Bishal's Experiment A | Reviewed comparison CSV, classification totals, attack transformation results and testing screenshots |
| Sadaiba's R11 | Baseline effect checks, protected WAF observations, configuration reviews and false-positive controls |
| Sadaiba's R12 | Authenticated command separator testing, repeated protected observations and correlated server logs |
| Expanded benign testing | Additional benign request cases and their WAF blocking results |
| Earlier automated evaluation | Baseline, ModSecurity and Coraza attack and mixed traffic summaries |
| Individual Role 4 package | Python analysis scripts, validation records, comparison chart and technical documentation |

The integration branch contains both operational evidence and files generated to support testing. A generated test case is not automatically a completed attack experiment.

Software unit tests also do not independently establish that an actual WAF blocked a request in the live laboratory.

## 3. Experiment A: ModSecurity and NAXSI

Experiment A contains 1,684 reviewed request records per WAF.

Each WAF was assessed using 1,564 malicious-labelled requests and 120 benign-labelled requests.

### 3.1 Classification results

| Classification | ModSecurity | NAXSI |
|---|---:|---:|
| True positives | 1,564 | 1,310 |
| False negatives | 0 | 254 |
| False positives | 11 | 12 |
| True negatives | 109 | 108 |

A true positive is a malicious-labelled request that the WAF blocks. A false negative is a malicious-labelled request that the WAF allows.

A false positive is a benign-labelled request that is blocked. A true negative is a benign-labelled request that is allowed.

### 3.2 Detection effectiveness

| Metric | ModSecurity | NAXSI |
|---|---:|---:|
| Recall | 100.00% | 83.76% |
| Precision | 99.30% | 99.09% |
| False-positive rate | 9.17% | 10.00% |
| Accuracy | 99.35% | 84.20% |

These values were calculated using confusion-matrix counts.

The `validate_waf_evidence.py` program checked the reviewed Experiment A comparison file and confirmed that all eight classification counts matched the reported totals.

The successful output was saved in `validation_results.txt`.

This establishes agreement between the reviewed classifications and reported results. It does not independently confirm every original request against raw server logs.

## 4. Experiment A: Missed Detections and Transformations

The `analyze_naxsi_misses.py` program examined requests labelled as NAXSI false negatives.

The analysis identified 254 missed detections.

### 4.1 False negatives by attack category

| Category | False negatives |
|---|---:|
| XSS | 120 |
| SQL injection | 92 |
| Path traversal | 42 |
| **Total** | **254** |

### 4.2 False negatives by transformation

| Transformation | False negatives |
|---|---:|
| Baseline | 42 |
| Double encoding | 212 |
| **Total** | **254** |

The additional CSV files supplied by Bishal confirmed that the double-encoded subset contained 240 malicious-labelled requests per WAF.

| Double-encoded category | ModSecurity blocked | NAXSI blocked | NAXSI allowed |
|---|---:|---:|---:|
| SQL injection | 120 | 28 | 92 |
| XSS | 120 | 0 | 120 |
| **Total** | **240** | **28** | **212** |

ModSecurity detected 100% of the tested double-encoded requests. NAXSI detected 11.67%.

These observations indicate a detection weakness for the tested double-encoded payloads under the evaluated NAXSI configuration.

However, a malicious-labelled request being allowed does not necessarily establish successful backend exploitation.

## 5. R11: Controlled Three-WAF Testing

Sadaiba's R11 evidence contains 225 protected observations.

The experiment included 21 validated attack cases and four benign controls. Each case was repeated three times against ModSecurity, Coraza and NAXSI.

This produced 189 attack observations and 36 benign control observations across the three WAFs.

### 5.1 Attack detection

| WAF | Attack observations blocked | Attack observations allowed |
|---|---:|---:|
| ModSecurity | 63/63 | 0 |
| Coraza | 63/63 | 0 |
| NAXSI | 60/63 | 3 |

ModSecurity and Coraza blocked every attack observation included in this R11 protected set.

NAXSI allowed three repetitions of one newline separator command injection case, identified as `R11-CMD-E03`.

The repeated misses were attributed in the project review to a coverage gap in the preserved NAXSI configuration snapshot. This finding must not be generalised to all possible NAXSI configurations.

### 5.2 Initial benign controls

| WAF | Benign observations blocked | Benign observations allowed |
|---|---:|---:|
| ModSecurity | 0/12 | 12 |
| Coraza | 0/12 | 12 |
| NAXSI | 3/12 | 9 |

The three NAXSI blocked observations corresponded to a small set of deliberately attack-like benign requests.

These results are useful for understanding configuration behaviour. They are not a population-level false-positive estimate.

### 5.3 Baseline exclusions

Three R11 double-encoded candidates did not establish their intended application effect before protected testing.

These were `R11-SQLI-E03`, `R11-XSS-E04` and `R11-PTH-E03`.

They were excluded from the effective attack denominator.

This exclusion is important because a request that does not work against the unprotected application cannot be counted as a demonstrated WAF prevention success.

## 6. R12: Command Separator Testing

Sadaiba's R12 experiment examined command injection requests that varied the command separator and space encoding.

The corrected runner used an authenticated DVWA session and an explicit low security setting.

The valid baseline contained 10 cases tested three times. Eight attack candidates passed the intended effect check, one benign control passed, and one double-encoded negative control failed the effect check.

The protected phase used nine eligible cases across three WAFs and three repetitions, producing 81 observations.

### 6.1 Protected attack results

| WAF | Attack cases blocked | Attack cases missed |
|---|---:|---:|
| ModSecurity | 8/8 | 0 |
| Coraza | 8/8 | 0 |
| NAXSI | 6/8 | 2 |

Each attack case was repeated three times.

NAXSI missed both newline separator variants, with `%20` and `+` space encodings. Both misses were observed in all three repetitions, producing six allowed attack observations.

The R12 continuity record states that these six cases were corroborated using command output in the client response, matching server access records and the absence of corresponding WAF block events.

### 6.2 Interpretation

The R12 findings indicate that the observed NAXSI weakness concerned the newline command separator in the evaluated configuration.

The same weakness was not observed for the semicolon, logical AND or pipe separators in that controlled test set.

The results also show why validation against actual application behaviour is necessary. HTTP status codes alone are not sufficient to establish a successful command injection effect.

### 6.3 Invalidated runs

Five earlier R12 baseline runs used a defective runner that did not establish the required authenticated session.

Those requests received redirects rather than executing the intended test cases.

The project record explicitly invalidates those runs. They must not be included in the research results.

## 7. Expanded Benign Request Testing

The R11 follow-up introduced four additional benign cases containing text that resembled command injection, path traversal or SQL keywords.

The cases were first checked against the unprotected application to confirm normal handling.

They were then sent through ModSecurity, Coraza and NAXSI, with three repetitions per case.

| WAF | Additional benign observations blocked | Additional benign observations allowed |
|---|---:|---:|
| ModSecurity | 0/12 | 12 |
| Coraza | 0/12 | 12 |
| NAXSI | 12/12 | 0 |

NAXSI blocked all 12 additional benign observations. ModSecurity and Coraza allowed all 12.

This indicates that the evaluated NAXSI configuration was more restrictive for this small selection of legitimate, attack-like text.

It does not mean that NAXSI would block all normal user traffic. The additional corpus contained only four deliberately selected benign cases.

The original and expanded benign sets should remain distinguishable in reporting unless their full combined evidence is explicitly reviewed.

## 8. Earlier Automated ModSecurity and Coraza Evaluation

The integrated repository also includes automated experiments using baseline traffic, ModSecurity and Coraza.

These experiments examined attack-only traffic and mixed benign and malicious traffic.

The original records are stored in the project's `output/` directories. Summary files are provided under `analysis/final/`.

The attack categories include SQL injection, XSS, brute force, JavaScript-related requests, CSRF, weak session identifiers and authorisation bypass.

The automated evaluation provides useful observations about different classes of web application weaknesses.

However, its request corpus and classification rules differ from Experiment A and R11/R12.

These results must therefore be presented as a separate evaluation rather than merged into one combined detection rate.

### 8.1 Reported classification observations

The integrated summary identifies blocking of selected SQL injection and XSS requests by ModSecurity and Coraza.

It also reports limited blocking for application logic weaknesses such as CSRF, weak session identifiers and authorisation bypass.

This distinction is consistent with the role of a WAF as a request inspection control, rather than a replacement for application security controls.

### 8.2 Evidence consistency issue

The `analysis/final/confusion_matrices.csv` file contains some rows where the reported attack row count differs from the sum of true positives and false negatives.

For example, the ModSecurity attack-only row reports 465 attack rows, but 162 true positives and 282 false negatives, which total 444.

The difference is 21 records.

The summary therefore requires reconciliation of excluded, unclassified or otherwise omitted requests before its recall values can be treated as fully confirmed.

Until that review is completed, these figures should be described as reported automated evaluation results, not independently verified final classification totals.

## 9. Performance and Latency

The group's evidence includes two different meanings of performance.

The file named `performance_metrics.csv` in Bishal's results contains classification metrics such as recall, precision, accuracy and F1-score.

It does not contain timing or resource measurements.

The earlier automated evaluation provides client-observed response-time measurements.

| WAF | Attack-only average latency | Mixed traffic average latency |
|---|---:|---:|
| No WAF | 6.196 ms | 6.220 ms |
| ModSecurity | 7.946 ms | 9.925 ms |
| Coraza | 9.022 ms | 16.686 ms |

These values are reported in `analysis/final/report_summary.md`.

They describe end-to-end response times in the recorded runs.

The observed differences include the combined effects of application processing, network communication, workload conditions and WAF inspection.

Without additional controlled measurements, they should not be described as isolated WAF processing overhead.

The performance comparison also does not include NAXSI data in this automated evaluation.

## 10. Cross-Experiment Interpretation

The combined evidence supports several observations.

First, ModSecurity and Coraza blocked all validated attack observations in the specific R11 and R12 protected test sets.

Second, NAXSI showed misses involving double-encoded requests in Experiment A and newline separator command injection in R11 and R12.

Third, the expanded benign testing identified multiple false-positive blocks by the evaluated NAXSI configuration.

Fourth, earlier automated experiments show that WAF detection is not equally effective across all classes of web application weaknesses.

These findings do not establish a universal ranking of WAF products.

The experiments differ in attack types, application state, WAF configuration, logging evidence, repetition counts and benign traffic selection.

A WAF that performs well on one corpus cannot automatically be assumed to perform equally well on all applications or configurations.

## 11. Individual Role 4 Contribution

My individual contribution includes developing and executing three Python programs:

1. `analyze_waf_results.py`, which calculates metrics from reported aggregate data and produces a comparison CSV and chart.
2. `validate_waf_evidence.py`, which checks reviewed Experiment A classification records and reported confusion-matrix totals.
3. `analyze_naxsi_misses.py`, which groups NAXSI missed detections by attack category and transformation variant.

I also prepared `README.md`, `DATA_VALIDATION.md` and `TRANSFORMATION_AND_PERFORMANCE_REVIEW.md` to explain the data sources, calculations, software tests and interpretation limits.

This integrated review extends that work by comparing available evidence from Bishal, Sadaiba and the earlier automated evaluation.

The original WAF configuration, attack execution, baseline effect verification and server log collection were performed by other project team members.

My role is to consolidate and interpret their available evidence while maintaining a clear distinction between reported and independently checked findings.

## 12. Limitations and Outstanding Verification

The principal limitations of the integrated evidence are:

1. Different experiments use different request corpora and denominators.
2. Some classification summaries contain count discrepancies requiring reconciliation.
3. Malicious requests allowed by a WAF do not always demonstrate successful application exploitation.
4. Some baseline attack candidates were excluded because their intended application effect was not confirmed.
5. The R11 and R12 benign controls are purposively selected and do not represent all legitimate user traffic.
6. Software validation tests do not replace live WAF testing.
7. Earlier automated latency measurements do not isolate WAF processing overhead.
8. XML and XXE testing was not established as completed in the reviewed R11 and R12 evidence.
9. The team's final integrated evidence audit remains pending.

These limitations should be stated in the final group report instead of being hidden or treated as successful test outcomes.

## 13. Conclusion

The integrated evidence demonstrates that WAF effectiveness depends on the type of request, the transformation used and the active rule configuration.

Experiment A showed high reported classification recall for ModSecurity and lower recall for NAXSI, with many NAXSI misses concentrated in double-encoded requests.

The separately documented R11 and R12 experiments identified a reproducible NAXSI newline separator command injection weakness, supported by application effect checks and correlated logs.

The expanded benign tests also showed that stronger blocking of suspicious looking text can interfere with legitimate requests.

Taken together, these findings support a practical conclusion: WAF effectiveness should be evaluated using both malicious and benign traffic, with application effect validation, repeatable test cases and preserved evidence.

The work also highlights the need to distinguish classification metrics from performance measurements and to avoid combining experiments that use incompatible datasets.

This document provides an evidence review for the final group report. Any outstanding summary discrepancies should be resolved before the associated figures are presented as final verified results.

## 14. Evidence References

The supporting project paths are:

- `contributions/pabin/`
- `contributions/pabin/reviewed_group_evidence/`
- `contributions/bishal/Final_Evidence/Results/`
- `experiments/r11-r12/WORK_SYNC.md`
- `experiments/r11-r12/WORK_SYNC_PROTECTED.md`
- `experiments/r11-r12/evidence/`
- `analysis/final/report_summary.md`
- `analysis/final/confusion_matrices.csv`
- `VALIDATION.md`

All references use the group's `comp6016-final-integration` branch. The final report should record the exact integration commit used during final evidence verification.
