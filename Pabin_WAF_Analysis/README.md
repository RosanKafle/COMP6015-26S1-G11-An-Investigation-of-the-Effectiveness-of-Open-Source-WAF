# WAF Results Analysis and Validation

**Student:** Pabin Gurung  
**Student ID:** 22343460  
**Course:** COMP6016 Computer Science Project 2  
**Group:** 11  
**Role:** Measurement, Analysis and Documentation Lead

## 1. Project Overview

This folder contains my WAF results analysis and validation work for the project, *An Investigation of the Effectiveness of Open-Source Web Application Firewalls*.

The work focuses on checking reported results, calculating detection metrics, identifying data errors and presenting results in tables and graphs.

The analysis covers ModSecurity, NAXSI and Coraza. The experiments are kept separate because they use different datasets.

## 2. Files and Their Purpose

| File | Purpose |
|---|---|
| `analyze_waf_results.py` | Calculates WAF detection metrics and generates a comparison CSV and chart. |
| `validate_waf_evidence.py` | Checks the reviewed Experiment A request classifications. |
| `analyze_naxsi_misses.py` | Counts NAXSI false negatives by category and payload variant. |
| `reported_aggregates.json` | Contains previously reported group results for Experiments A and B. |
| `waf_comparison.csv` | Generated table showing recall, precision, false-positive rate and accuracy. |
| `waf_detection_chart.png` | Generated comparison chart for both experiments. |
| `validation_results.txt` | Saved output from the successful Experiment A validation. |
| `naxsi_misses_results.txt` | Saved output from the NAXSI missed-detection analysis. |
| `DATA_VALIDATION.md` | Documents the source evidence, checks and limitations. |
| `requirements.txt` | Lists the external Python library required for chart generation. |
| `.gitignore` | Prevents temporary and local source files from being uploaded. |

## 3. Development Environment

The programs were executed on macOS using Python 3.13.7.

Python's built-in CSV and JSON libraries were used to process the data. Matplotlib was used to generate the comparison chart.

The original WAF experiments were conducted by the project team in a controlled laboratory environment. These analysis programs do not launch attacks or configure the WAFs.

## 4. How to Run the Programs

Open Terminal inside the `Pabin_WAF_Analysis` folder.

Install the required library if needed:

```bash
python3 -m pip install -r requirements.txt
```

Run the aggregate results analysis:

```bash
python3 analyze_waf_results.py
```

This generates `waf_comparison.csv` and `waf_detection_chart.png`.

For request-level validation, obtain the reviewed Experiment A comparison CSV from the group evidence archive and save it locally as `source_comparison.csv`.

Run:

```bash
python3 validate_waf_evidence.py source_comparison.csv
```

To analyse NAXSI missed detections, run:

```bash
python3 analyze_naxsi_misses.py
```

The two request-level programs require `source_comparison.csv`, which is kept locally and is not included in this GitHub folder.

## 5. Evaluation Metrics

Four confusion-matrix values are used:

- TP: malicious-labelled request blocked.
- TN: normal-labelled request allowed.
- FP: normal-labelled request blocked.
- FN: malicious-labelled request allowed.

The calculations are:

- Recall = TP / (TP + FN) × 100
- Precision = TP / (TP + FP) × 100
- False-positive rate = FP / (FP + TN) × 100
- Accuracy = (TP + TN) / (TP + TN + FP + FN) × 100

The results are calculated separately for each WAF and experiment.

## 6. Experiment A Validation

The reviewed Experiment A comparison CSV contained 1,684 request records.

The validation program checked required columns, missing and duplicate test identifiers, record count, classification labels and reported confusion-matrix totals.

| Classification | ModSecurity | NAXSI |
|---|---:|---:|
| True positives | 1,564 | 1,310 |
| True negatives | 109 | 108 |
| False positives | 11 | 12 |
| False negatives | 0 | 254 |

All eight classification counts matched the previously reported results.

The program displayed `VALIDATION PASSED`.

## 7. Software Testing

The aggregate-analysis program was tested using a negative true-positive value in a temporary input file. The program rejected the value.

The request-level validation program was tested using a separate CSV containing a duplicated test identifier.

The program rejected the modified CSV with:

`ValueError: Duplicate test IDs found`

The original source dataset was not modified.

## 8. Data Management and Limitations

The reviewed Experiment A comparison CSV was obtained from the group's preserved evidence archive.

The original archive was retained, and a separate working copy was used for analysis.

The source location and SHA-256 checksum are recorded in `DATA_VALIDATION.md`.

The validation confirms consistency between the reviewed classification records and reported results. It does not independently prove every original WAF decision.

Experiment B uses a separate dataset involving ModSecurity, Coraza and NAXSI. Its current aggregate figures have not yet been independently reconciled against the latest request-level evidence.

An allowed malicious-labelled request does not necessarily indicate successful exploitation.

The available end-to-end response-time measurements do not isolate WAF processing overhead.

## 9. Future Work

Further improvements could include checking each classification against original WAF and backend logs, extending the validation programs to new datasets and automatically generating discrepancy reports.

Additional evidence from other team members should be reviewed separately before inclusion in the final research comparison.

## 10. NAXSI Missed-Detection Analysis

The `analyze_naxsi_misses.py` program examines the reviewed Experiment A comparison CSV and counts NAXSI false negatives by attack category and payload variant.

The analysis confirmed 254 recorded false negatives.

### Misses by attack category

| Category | False negatives |
|---|---:|
| XSS | 120 |
| SQL injection | 92 |
| Path traversal | 42 |
| **Total** | **254** |

### Misses by payload variant

| Variant | False negatives |
|---|---:|
| Double encoding | 212 |
| Baseline | 42 |
| **Total** | **254** |

The results matched the previously reported group figures.

To reproduce this analysis, place the reviewed Experiment A CSV in this folder as `source_comparison.csv`, then run:

```bash
python3 analyze_naxsi_misses.py
```

The output can be saved in `naxsi_misses_results.txt`.

These results confirm the false-negative counts in the reviewed classification data. They do not establish that every allowed malicious request successfully exploited the application.
