# COMP6016 — Testing and Quality Assurance Guide

**Project:** An Investigation of the Effectiveness of Open-Source Web Application Firewalls  
**Contributor:** Bishal Giri (22902243), Group 11  
**Supervisor:** Mihai Lazarescu  
**Scope:** ModSecurity/OWASP CRS and Nginx/NAXSI workstream; saved experimental evidence and offline analysis  
**Document purpose:** Progress Report 3 — *Testing & Quality: Information on project testing and known issues*.

> **Evidence boundary:** This guide documents the recorded experiments and review results. It does not certify a new live WAF test, a clean-room redeployment, the entire team's Coraza work, or successful application exploitation for every attack-labelled request. File paths refer to the original Kali project (`~/waf-semester2`) unless otherwise stated. File names should be checked on the receiving machine.

## 1. Test objectives and acceptance approach

The ModSecurity/NAXSI workstream assessed whether each WAF condition correctly **blocked malicious-labelled requests** and **allowed benign-labelled requests**, and whether a matched corpus could be evaluated reproducibly. Testing also examined the impact of attack category and payload representation on detection, and preserved evidence supporting review of WAF decisions.

The evaluation used four classes: **SQL injection (SQLi), cross-site scripting (XSS), command injection and path traversal**. The final reviewed corpus comprised **1,684 cases for each WAF**, of which **1,564 were malicious-labelled and 120 benign-labelled**. This included **600 baseline cases** and **1,084 generated variants**. The same labelled case set was matched across ModSecurity and NAXSI.

A *pass* for the testing framework means the request was executed and its reviewable outcome was recorded consistently; it does **not** mean the WAF successfully blocked every attack. A WAF detection miss is a valid test finding, not necessarily a test-framework failure.

## 2. Testing coverage and evidence

| Test area | Purpose and approach | Relevant evidence | Status within recorded scope |
|---|---|---|---|
| Controlled lab and WAF setup | Kali testing client, Ubuntu/DVWA/Apache target, alternate ModSecurity and NAXSI enforcement | `Week_07/docs/architecture.md`; `Week_06/logs/week06-modsecurity-clean/`; `Week_06/logs/week06-naxsi-clean/` | Recorded configuration and runs exist; live current-state verification pending |
| Baseline and matched-case execution | Common test identifiers and source cases under both WAFs | `Week_05/results/raw/`; `Week_06/results/raw/`; `Week_06/results/processed/comparison.csv` | Completed for recorded matched runs |
| Attack categories | SQLi, XSS, command injection, path traversal | `Week_06/test_cases/`; category CSVs and charts | Completed in reviewed corpus |
| Payload variants | Case, comments, double encoding, encoding, separators, URL encoding, whitespace | `Week_06/test_cases/variants/generated_variants.csv`; `Week_06/outputs/variant_semantic_validation.csv` | Generated and labelled; semantic implications require careful interpretation |
| Evidence-based classification | Correlate WAF signals and Apache backend observations; avoid status-only assumptions | Reviewed decisions CSVs; ModSecurity audit log; NAXSI access/error and Apache backend logs | Completed for saved reviewed runs |
| Quantitative evaluation | Confusion matrices, precision/recall/F1, specificity, false-positive and false-negative rates | `Week_07/results/processed/*/metrics.json`; `Final_Submission/Evidence/Results/` | Validated against saved comparisons |
| Timing | Client-observed median and p95 latency | `Week_07/results/processed/*/latency.json` | Descriptive measurements only; not isolated WAF overhead |
| Integrity and handover | Preserve raw data and validate copied evidence hashes | `Final_Submission/evidence_manifest.csv`; `Final_Submission/Evidence/Logs/evidence_sha256.txt` | Verified for declared evidence scope, not necessarily every file in expanded archive |

### Recorded run identifiers

- Week 5 ModSecurity baseline: `20260921T155000Z_d194f19db17d`
- Week 5 NAXSI baseline: `20260921T164645Z_a1ab5dc9e495`
- Week 6 reviewed ModSecurity: `20260922T081541Z_d78b12c20b69`
- Week 6 reviewed NAXSI: `20260922T084234Z_e864a464e30f`

Do not combine these with the team's distinct R11/R12 or Coraza experiment populations without a documented common denominator and equivalent test conditions.

## 3. Classification and quality rules

The review framework applies:

| Label | Attack label | Evidence-supported WAF disposition |
|---|---|---|
| TP | Malicious | Blocked |
| FN | Malicious | Allowed |
| TN | Benign | Allowed |
| FP | Benign | Blocked |

An HTTP `403` alone does **not** prove a WAF intervention; a backend can generate it. Likewise, HTTP `200` alone does **not** establish that malicious code ran or that the payload succeeded. The classification process uses reviewed WAF evidence and proxy/backend log correlation. Ambiguous, skipped or error cases should be left **UNKNOWN/unreviewed** rather than assigned a forced result. The stored reviewed matched experiment reports no remaining UNKNOWN/ERROR/SKIPPED rows; this does not imply that future runs will have none.

### Logged correlation examples

Representative reviewed NAXSI misses include:

- `SQLI_0090_DOUBLEENC` — double-encoded SQL injection; stored disposition **ALLOWED**.
- `XSS_0022_DOUBLEENC` — double-encoded XSS; stored disposition **ALLOWED**.
- `PATH_TRAVERSAL_0015` — baseline traversal; stored disposition **ALLOWED**.

The preserved NAXSI access and Apache backend logs contain request identifiers (`rid=`), enabling a single request to be traced across the proxy and backend. The prior handover review reported exact access/backend request-ID matches for the 254 recorded NAXSI misses, with 200 responses. This supports passage to the backend under the reviewed classification; it does not independently establish successful exploitation for every request. Do not use unrelated log lines as a claimed matched pair.

## 4. Verified classification results

| Metric | ModSecurity | NAXSI |
|---|---:|---:|
| Total matched requests | 1,684 | 1,684 |
| Malicious requests | 1,564 | 1,564 |
| Benign requests | 120 | 120 |
| True positives | 1,564 | 1,310 |
| True negatives | 109 | 108 |
| False positives | 11 | 12 |
| False negatives | 0 | 254 |
| Precision | 99.30% | 99.09% |
| Recall | 100.00% | 83.76% |
| F1-score | 99.65% | 90.78% |
| Specificity | 90.83% | 90.00% |
| False-positive rate | 9.17% | 10.00% |
| False-negative rate | 0.00% | 16.24% |
| Accuracy | 99.35% | 84.20% |

**Interpretation:** In this particular matched corpus and configuration, ModSecurity had higher recall, while both WAFs blocked some benign traffic. The dataset is malicious-heavy; accuracy alone is not a reliable indicator of production behaviour.

### Detection by category

| Malicious category | Cases | ModSecurity detected | NAXSI detected | NAXSI missed |
|---|---:|---:|---:|---:|
| Command injection | 120 | 120 | 120 | 0 |
| Path traversal | 120 | 120 | 78 | 42 |
| SQL injection | 724 | 724 | 632 | 92 |
| XSS | 600 | 600 | 480 | 120 |
| **Total** | **1,564** | **1,564** | **1,310** | **254** |

### Detection by payload transformation (malicious requests only)

| Transformation | Cases | ModSecurity detected | NAXSI detected | NAXSI recall |
|---|---:|---:|---:|---:|
| Baseline | 480 | 480 | 438 | 91.25% |
| Case | 190 | 190 | 190 | 100.00% |
| Comments | 98 | 98 | 98 | 100.00% |
| Double encoding | 240 | 240 | 28 | 11.67% |
| Encoding | 120 | 120 | 120 | 100.00% |
| Separators | 98 | 98 | 98 | 100.00% |
| URL encoding | 240 | 240 | 240 | 100.00% |
| Whitespace | 98 | 98 | 98 | 100.00% |

The **254** NAXSI misses comprise **212 double-encoded** (120 XSS, 92 SQLi) and **42 baseline path-traversal** cases. The precise causes (normalisation, decoding, rule selection, threshold or backend interpretation) have not been isolated by a controlled before/after tuning study.

## 5. Recorded client response times

| Measure | ModSecurity | NAXSI |
|---|---:|---:|
| Recorded requests | 1,684 | 1,684 |
| Median response time | 8.6795 ms | 4.8400 ms |
| 95th percentile | 53.492 ms | 48.407 ms |

These are end-to-end client observations including transport and backend effects. They do **not** establish isolated firewall overhead, statistically significant speed differences, throughput limits or scaling behaviour. No independently repeated matched load benchmark is established by this workstream's reviewed data.

## 6. Read-only quality checks — KALI

All commands below operate on saved data. They do not send traffic to DVWA. Open a Kali terminal:

```bash
cd ~/waf-semester2
source .venv/bin/activate
```

**A. Confirm saved metric counts:**

```bash
python - <<'PY'
import json
from pathlib import Path
for name in ('modsecurity', 'naxsi'):
    p = Path(f'Week_07/results/processed/{name}-week6/metrics.json')
    m = json.loads(p.read_text())
    print(name, {k:m[k] for k in ('TP','TN','FP','FN')})
PY
```

Expected: ModSecurity `1564, 109, 11, 0`; NAXSI `1310, 108, 12, 254`.

**B. Run the read-only metric calculation on the reviewed inputs:**

```bash
python Week_07/analysis/metrics.py --input \
  Week_06/results/processed/20260922T081541Z_d78b12c20b69-reviewed.csv
python Week_07/analysis/metrics.py --input \
  Week_06/results/processed/20260922T084234Z_e864a464e30f-reviewed.csv
```

Review `python Week_07/analysis/metrics.py --help` before executing if the installed version differs. Do not run any scripts with `--execute` during evidence-only verification.

**C. List supporting logs and outputs:**

```bash
ls -lh Week_06/logs/week06-modsecurity-clean/
ls -lh Week_06/logs/week06-naxsi-clean/
ls -lh Final_Submission/Evidence/Results/
```

**D. Verify recorded evidence-copy hashes:**

```bash
sha256sum -c Final_Submission/Evidence/Logs/evidence_sha256.txt
```

If an expected file is absent after extraction, inspect the package's actual layout rather than constructing a replacement result or modifying the source data.

## 7. Known issues, risks and status

| Issue / limitation | Impact | Status / recommended follow-up |
|---|---|---|
| NAXSI double-encoded misses (212) | Large reduction in recall for that transformation | Confirmed finding; investigate actual effective rule/decoding chain; run controlled regression after any tuning |
| NAXSI baseline path-traversal misses (42) | Traversal category recall 65% | Confirmed finding; review rule scope and backend interpretation |
| Benign false positives (11 ModSecurity, 12 NAXSI) | Legitimate requests blocked during the test | Confirmed counts; review individual cases before rule tuning |
| Payload semantic equivalence | Transformed raw bytes may change meaning after decoding | Approval/validation records retained; do not assume all variants were independently verified as successful exploits |
| Status-only interpretation | Misattributes backend responses to WAF | Addressed in reviewed evidence workflow; continue requiring correlated evidence |
| ModSecurity audit warnings | Warning does not imply block | Preserve distinction between rule event and disruptive action |
| DVWA session and redirects | Login-page responses can distort outcome interpretation | Saved notes exist; future replay must verify authenticated session and response content |
| Host-only/NAT configuration | Internet updates may change VM routing/isolation | Historical troubleshooting performed; recheck routes and service exposure before future active tests |
| VirtualBox shared clipboard issue | Windows/Kali copy–paste sometimes failed | Operational inconvenience; VM restart was the user's workaround; not a WAF result |
| Complete clean-room reproduction | A new VM might not reproduce the historical services automatically | Not independently verified; requires setup, version, ruleset, credentials and network checks |
| Expanded archive privacy | Config/raw logs may include credentials, session cookies or tokens | Review/sanitize public copies; never upload unreviewed raw artefacts to a public repo |
| Historical timing comparisons | Different content, request conditions and lack of repetitions confound speed rankings | Report descriptive latency only; build matched benchmark for future work |
| Coraza / team R11-R12 / expanded corpus v2 | Different test populations and validation procedures | Handle in distinct team sections; never pool numerators/denominators into Experiment A |

## 8. Test quality controls and handover rules

1. Preserve original raw evidence as read-only; create new derived outputs in separate folders.
2. Retain original **run ID**, **test ID**, **request ID**, corpus digest and configuration evidence when present.
3. Use matched labelled requests and state denominators explicitly.
4. Keep **UNKNOWN**, failed and skipped cases separate; never convert them into TP/TN/FP/FN without evidence.
5. Require a clear link between a classification and WAF/backend evidence, not HTTP status alone.
6. Retain both benign and malicious samples to calculate FPR as well as recall.
7. Record modifications to WAF rules and use fresh run IDs and controlled before/after regression cases.
8. Review secrets and personal/session data before publishing any logs, code or configs.
9. Keep separate experiment populations separate in the final report.
10. State what testing verifies and what remains untested.

## 9. Remaining verification and future work

- Independently restore the virtual laboratory and record precise OS, WAF engine, CRS/NAXSI ruleset, Nginx/Apache, ZAP and Python dependency versions.
- Verify live listener ports, effective WAF enforcement, Ubuntu backend path, authenticated DVWA workflow and restricted host-only exposure.
- Run a small authorised smoke test with recorded expected dispositions and no modification to historical run directories.
- Conduct targeted NAXSI rule/normalisation testing on the 212 double-encoded and 42 traversal misses, using pre/post configuration snapshots.
- Investigate the individual false-positive requests and the effect of approved rule tuning.
- Repeat matched workloads with controlled concurrency, resource use, response size and latency; report variability.
- Independently validate sample payload semantics and application effects, particularly under multiple decoding stages.
- Complete a clean extracted-package offline reproduction check and record outputs and hashes.
- Incorporate the separate Coraza and team experimental evidence only with clearly distinct populations and ownership.

## 10. Evidence directory quick reference

```text
~/waf-semester2/
├── Week_01/ ... Week_07/             # Historical project work
├── Week_05/results/raw/               # Preserved baseline runs
├── Week_06/test_cases/                # Labelled input cases and variants
├── Week_06/outputs/                   # Variant semantic-validation record
├── Week_06/results/raw/               # Raw request results and run artefacts
├── Week_06/results/processed/         # Reviewed outcomes / decisions / comparison
├── Week_06/logs/week06-modsecurity-clean/
├── Week_06/logs/week06-naxsi-clean/
├── Week_07/results/processed/         # Metrics, categories, missed cases, latency
├── Final_Submission/Evidence/Results/ # Generated charts and analytical CSVs
├── Final_Submission/Evidence/Logs/    # Preserved WAF/backend evidence copies
└── Final_Submission_Complete/         # Expanded handover packaging
    ├── Project/Week_01/ ... Week_07/
    └── Final_Analysis/Results/
```

**Companion guides:** Project `README.md`, `Development_Environment_Setup.md`, and `Data_Management_Guide.md` should accompany this file under the handover documentation directory.

**Source and attribution note:** Data values and file locations reflect the reviewed COMP6016 project handover and experiment results in this workstream. Existence of a script or snapshot is not independent proof of sole authorship, present deployment state, production effectiveness or exploit success. Team-wide claims belong in the consolidated group report with separate attribution.
