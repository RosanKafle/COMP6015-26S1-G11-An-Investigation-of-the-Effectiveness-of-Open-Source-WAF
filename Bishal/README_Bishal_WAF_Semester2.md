# COMP6016 Semester 2 — ModSecurity and NAXSI WAF Evaluation

**Project:** An Investigation of the Effectiveness of Open-Source Web Application Firewalls  
**Contributor:** Bishal Giri (22902243), Group 11  
**Supervisor:** Mihai Lazarescu, Curtin University  
**Workstream:** WAF infrastructure, ModSecurity/NAXSI comparative experiments, evidence review, and reproducible analysis  
**Document date:** 25 October 2026  
**Status:** Handover guide for saved research artifacts. It is *not* a claim that the entire multi-member project or a clean-room live deployment has been independently verified.

## 1. What this repository contains

This workstream investigates how two configured open-source web application firewalls handled **matched benign and attack-labelled HTTP requests** directed at a controlled DVWA laboratory application:

- **ModSecurity + OWASP Core Rule Set (CRS)** with Apache.
- **NAXSI + Nginx** as an inspecting reverse proxy in front of Apache/DVWA.

A Kali Linux VM supplied tests and analysis; Ubuntu hosted the deliberately vulnerable application and the relevant WAF/server components. Historical tests used the VirtualBox host-only laboratory, with the retained NAXSI logs showing test-client `192.168.56.100`, application/WAF endpoint `192.168.56.20`, and an Apache backend listener on port `8080`. **These are historical evidence values, not addresses to assume for a new deployment.**

My preserved work covers the architecture and configuration records; Python request/test workflows; baseline and transformed test cases; raw and reviewed WAF observations; ModSecurity audit parsing; NAXSI proxy/backend correlation; confusion matrices and false-negative investigation; figures; and final evidence preservation. Other team members' Coraza and R11/R12 experiments are **separate research populations**, not additional rows of this matched ModSecurity/NAXSI experiment.

### Main research questions

1. How did the tested ModSecurity and NAXSI configurations distinguish legitimate and attack-labelled traffic?
2. Which attack categories and payload transformations were most often missed?
3. Can a recorded disposition be justified by WAF/server evidence, **without inferring a WAF block from HTTP status alone**?
4. What do recorded client-observed response times show, and what can they *not* establish about WAF overhead?

## 2. Repository and handover layout

The original Kali workspace was `/home/bishal/waf-semester2`. The **real, populated development directories were `Week_01` through `Week_07`**. Later synthesis and handover work is stored by *deliverable*, not as invented `Week_08`–`Week_13` experiment folders.

```text
waf-semester2/
├── .venv/                             # Kali Python virtual environment (not distributed)
├── Week_01/ ... Week_04/              # Earlier configs, scripts, documentation, tests/outputs
├── Week_05/
│   ├── config/ scripts/ docs/ analysis/
│   ├── results/raw/                   # Preserved original baseline runs
│   ├── results/processed/             # Derived/review outputs
│   └── logs/week05-{modsecurity,naxsi}-clean/
├── Week_06/
│   ├── config/test_config.json
│   ├── requirements.txt
│   ├── scripts/                       # Runner, loader, audit, evidence modules
│   ├── test_cases/                    # Benign and malicious input CSVs
│   │   └── variants/generated_variants.csv
│   ├── outputs/variant_semantic_validation.csv
│   ├── results/raw/                   # Original matched runs (do not modify)
│   ├── results/processed/             # Reviewed decisions and comparison.csv
│   └── logs/week06-{modsecurity,naxsi}-clean/
├── Week_07/
│   ├── scripts/
│   ├── analysis/                      # Metrics, category, latency, merge scripts
│   └── results/processed/
│       ├── modsecurity-week6/metrics.json
│       └── naxsi-week6/metrics.json
├── Final_Submission/
│   ├── Evidence/Results/              # Final PNG figures, summary CSVs, figure scripts
│   ├── Evidence/Logs/                 # Preserved copied server logs/configs
│   ├── evidence_manifest.csv
│   └── README.md
└── Final_Submission_Complete/
    ├── Project/Week_01/ ... Week_07/  # Copy of original weekly work
    ├── Final_Analysis/Results/        # Summary artifacts and figures
    ├── Final_Analysis/Logs/
    └── README.md
```

**Important:** `Final_Submission_Complete` was assembled as a separate delivery directory; older reduced ZIPs may omit early development files and raw evidence. The expanded local archive is named `COMP6016_Group11_BishalGiri_Complete_Code_Data.zip`. Confirm its integrity and the exact contents before submission. Paths above follow the Kali screenshots and saved reports; some analysis scripts use the original absolute workspace path and may require adjustment on another machine.

### Files most useful to a new reviewer

| Artifact | Why it matters |
|---|---|
| `Week_07/docs/architecture.md` | Experimental components and topology |
| `Week_06/scripts/run_test_set.py`, `request_runner.py`, `dvwa_session.py` | Automated request/session workflow |
| `Week_06/test_cases/{normal,sqli,xss,command_injection,path_traversal}.csv` | Standardised labelled inputs |
| `Week_06/test_cases/variants/generated_variants.csv` | Generated transformed requests |
| `Week_06/outputs/variant_semantic_validation.csv` | Recorded variant validity checks |
| `Week_06/results/processed/comparison.csv` | Matched ModSecurity/NAXSI reviewed outcomes |
| `Week_06/results/processed/*reviewed-decisions.csv` | Separate evidence-supported decisions |
| `Week_06/logs/week06-modsecurity-clean/modsecurity-audit.log` | ModSecurity audit/rule events |
| `Week_06/logs/week06-naxsi-clean/{naxsi-access.log,naxsi-error.log,apache-backend.log}` | NAXSI and backend correlation |
| `Week_07/results/processed/*/metrics.json` | Counts and scores for both WAFs |
| `Final_Submission/Evidence/Results/` | Final graphs and detailed analytical CSVs |
| `Final_Submission/evidence_manifest.csv` | File names, sizes and SHA-256 records |

## 3. Environment and prerequisites

**For historical evidence review (no live attacks):** a Linux computer with Python 3, access to the saved CSV/JSON files, and enough free disk space to extract the archive. Python's built-in `csv` and `json` modules suffice for the simple checks below. Plot recreation requires packages such as `numpy` and `matplotlib`, as used in the original Kali environment.

**For a new live reproduction (not yet independently demonstrated):** Oracle VirtualBox (or equivalent isolated VMs), Kali, Ubuntu, Apache with DVWA, ModSecurity and OWASP CRS, Nginx built with an operational NAXSI module/ruleset, valid DVWA credentials/session handling, matching HTTP transport configuration, and network isolation. **Do not point the attack scripts at public or unauthorised systems.**

On the original **KALI VM**, enter the existing workspace:

```bash
cd ~/waf-semester2
source .venv/bin/activate
python --version
```

To inspect the available package dependencies (no installation occurs):

```bash
cat Week_06/requirements.txt
python -m pip list
```

To prepare a new Python environment on a separately provisioned Linux system, after inspecting the requirements and paths:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r Week_06/requirements.txt
```

Installation requires network access and package availability, and dependencies may differ from the historical Kali VM. **The README does not claim that a clean installation has been tested.**

### Verify the lab before any new active tests

On **KALI** (client VM):

```bash
ip -br addr
ip route
```

On **UBUNTU** (WAF/backend VM):

```bash
ip -br addr
sudo ss -lntp
sudo nginx -t                 # Relevant if Nginx/NAXSI is enabled
sudo apache2ctl -t            # Relevant if Apache is enabled
```

Confirm by inspection that only the **intended** WAF condition is enforcing for the targeted port/location, the test host is authorised, the backend service is reachable, and DVWA is in the documented state. Historical configuration snapshots alone do not prove this. Only execute live runners after confirming their options and target controls; no live attack command is prescribed here.

## 4. Testing methodology and payload coverage

The principal matched reviewed evaluation supplied **1,684 requests to each WAF**:

- **120 benign-labelled** requests used to assess false positives.
- **1,564 malicious-labelled** requests across SQL injection, cross-site scripting (XSS), command injection and path traversal.
- **600 baseline** cases and **1,084 generated variants** across the full labelled corpus.

Variant groups included `case`, `comments`, `doubleenc`, `encoding`, `separators`, `urlenc`, and `whitespace`. Their exact test cases and transformed payload strings belong in the CSV files, not in a fictional example table. Use `test_id`, `parent_test_id`, `category`, `variant` and `transformation` to connect derived requests with their sources. The validation CSV records checks; it is not independent proof of semantic equivalence for every backend decoding path.

To examine *actual saved payloads* on **KALI**, without sending network traffic:

```bash
head -n 5 Week_06/test_cases/sqli.csv
head -n 5 Week_06/test_cases/xss.csv
head -n 5 Week_06/test_cases/command_injection.csv
head -n 5 Week_06/test_cases/path_traversal.csv
head -n 5 Week_06/test_cases/variants/generated_variants.csv
head -n 5 Week_06/outputs/variant_semantic_validation.csv
```

These files may include attack payloads, local credentials or HTTP session data: inspect locally before exposing the screen, uploading publicly or sharing example output.

### Saved experiment lineage

| Condition | Saved run identifier | Notes |
|---|---|---|
| ModSecurity clean baseline | `20260921T155000Z_d194f19db17d` | Week 5 raw baseline |
| NAXSI clean baseline | `20260921T164645Z_a1ab5dc9e495` | Week 5 raw baseline |
| ModSecurity reviewed experiment | `20260922T081541Z_d78b12c20b69` | Week 6 reviewed request results |
| NAXSI reviewed experiment | `20260922T084234Z_e864a464e30f` | Week 6 reviewed request results |

The Week 5 matched corpus SHA-256 recorded in the project history was `d93261a134549f8ac08935d013df2161dacc7acaaabb9072524ccf00bf946be7`. A hash only verifies content agreement when the **corresponding exact input file and method** are identified.

## 5. How the automation and review pipeline works

```text
Labelled test CSVs + configuration
            |
            v
Test loader -> payload variant generator / semantic checks
            |
            v
DVWA session management -> request runner -> ModSecurity OR NAXSI
            |
            v
Raw request records and HTTP observations (immutable)
            |
            +--> ModSecurity audit events / Apache request log
            |
            +--> NAXSI access/error log + Apache backend log
            |
            v
Evidence correlation and reviewed action CSVs
            |
            v
Join on matching test IDs -> comparison.csv -> metrics/categories/latency
            |
            v
Figures, tables, limitations and evidence manifest
```

Relevant saved scripts include `parse_modsecurity_audit.py`, `apply_evidence.py`, `merge_results.py`, `metrics.py`, `category_summary.py`, `latency_summary.py`, and the request/variant scripts. Their actual command-line flags **must be confirmed by reading each script or its `--help` output** before execution; do not assume a universal `--input` flag.

**Classification rule:** An HTTP status code is *not* sufficient evidence of a WAF action. HTTP 403 may originate at the backend; HTTP 200 does not prove exploitation. Interpret rule events and WAF decisions with correlated proxy/backend records. Keep execution failures, skipped records and insufficiently supported cases as `UNKNOWN`/unreviewed. Never rewrite raw results to make them agree with expected metrics.

The reviewed Experiment A contained **zero** UNKNOWN, ERROR or SKIPPED rows at final calculation time. That is a property of this reviewed dataset, not a rule for subsequent runs.

### Request correlation example

Saved NAXSI missed-detection test IDs include `SQLI_0090_DOUBLEENC`, `XSS_0022_DOUBLEENC`, and `PATH_TRAVERSAL_0015`. These records were reviewed as `ALLOWED`, with evidence notes describing pass-through and receipt at Apache. The project handover reports exact request-ID correlation for **254/254 NAXSI missed detections**. This supports the operational disposition but does *not* prove that all payloads achieved their exploit effects.

Examine one actual reviewed record (read-only) on **KALI**:

```bash
python - <<'PY'
import csv
p = 'Week_07/results/processed/naxsi-week6/missed_detections.csv'
with open(p, newline='', encoding='utf-8-sig') as f:
    for row in csv.DictReader(f):
        if row.get('test_id') == 'SQLI_0090_DOUBLEENC':
            for k in ('test_id','category','transformation','waf_action','http_status','notes'):
                print(k, ':', row.get(k, ''))
            break
PY
```

To see historical proxy/backend log formats without editing them:

```bash
head -n 3 Week_06/logs/week06-naxsi-clean/naxsi-access.log
head -n 3 Week_06/logs/week06-naxsi-clean/apache-backend.log
```

Compare **the same actual `rid=` value** between the two files; do not assume consecutive lines describe the same request. Preserve full source logs offline, and publish only approved sanitized excerpts.

## 6. Reproducing saved analysis safely (no network traffic)

Run these checks from the original **KALI** workspace or adjust paths after extraction.

**Inspect JSON metrics using only standard Python:**

```bash
cd ~/waf-semester2
python -m json.tool Week_07/results/processed/modsecurity-week6/metrics.json
python -m json.tool Week_07/results/processed/naxsi-week6/metrics.json
```

**Inspect the matched CSV schema and first rows:**

```bash
python - <<'PY'
import csv
p = 'Week_06/results/processed/comparison.csv'
with open(p, newline='', encoding='utf-8-sig') as f:
    reader = csv.DictReader(f)
    print('COLUMNS:', reader.fieldnames)
    for i, row in zip(range(3), reader):
        print(row)
PY
```

**Read the analysis script interfaces before running them:**

```bash
sed -n '1,180p' Week_07/analysis/metrics.py
sed -n '1,180p' Week_07/analysis/merge_results.py
sed -n '1,160p' Final_Submission/Evidence/Results/generate_figures.py
```

Do not run these blindly: some original scripts may write to fixed paths. If they accept output-directory arguments, use a **new** `demo_outputs/` directory; otherwise make a separate copy of the project first. The historically observed figure generator (in the original workspace) was run as:

```bash
python Final_Submission/Evidence/Results/generate_figures.py
```

That prior run generated confusion-matrix and comparison figures, but may overwrite derived PNGs; execute on a working copy if preserving final artifacts. `matplotlib` and `numpy` must be installed for plotting.

For checked preservation evidence, the earlier verified checksum command was:

```bash
sha256sum -c Final_Submission/Evidence/Logs/evidence_sha256.txt
```

That checksum list applies only to the files named in it. The source history reports 14 log/config checks passing and a 31-file evidence inventory; it does not certify every item in the expanded ZIP.

**Verify the expanded archive on KALI:**

```bash
unzip -t COMP6016_Group11_BishalGiri_Complete_Code_Data.zip | tail -n 2
unzip -Z1 COMP6016_Group11_BishalGiri_Complete_Code_Data.zip | grep -E 'Final_Submission_Complete/Project/Week_0[1-7]/$'
```

## 7. Verified findings from the reviewed matched experiment

| Classification / measure | ModSecurity | NAXSI |
|---|---:|---:|
| Total requests | 1,684 | 1,684 |
| True positives (TP) | 1,564 | 1,310 |
| True negatives (TN) | 109 | 108 |
| False positives (FP) | 11 | 12 |
| False negatives (FN) | 0 | 254 |
| Precision | 99.30% | 99.09% |
| Recall | 100.00% | 83.76% |
| F1 | 99.65% | 90.78% |
| Specificity | 90.83% | 90.00% |
| False-positive rate | 9.17% | 10.00% |
| Accuracy | 99.35% | 84.20% |

These values describe the **reviewed classification of the tested configurations and labelled corpus**, not a universal ranking or independently verified exploitation success.

### Attack category findings (malicious-labelled requests)

| Category | Cases | ModSecurity detected | NAXSI detected | NAXSI missed |
|---|---:|---:|---:|---:|
| Command injection | 120 | 120 | 120 | 0 |
| Path traversal | 120 | 120 | 78 | 42 |
| SQL injection | 724 | 724 | 632 | 92 |
| XSS | 600 | 600 | 480 | 120 |
| **Total** | **1,564** | **1,564** | **1,310** | **254** |

### Transformation findings (malicious-labelled requests)

| Transformation | Cases | ModSecurity TP | NAXSI TP | NAXSI FN |
|---|---:|---:|---:|---:|
| Baseline | 480 | 480 | 438 | 42 |
| Case | 190 | 190 | 190 | 0 |
| Comments | 98 | 98 | 98 | 0 |
| Double encoding | 240 | 240 | 28 | 212 |
| Encoding | 120 | 120 | 120 | 0 |
| Separators | 98 | 98 | 98 | 0 |
| URL encoding | 240 | 240 | 240 | 0 |
| Whitespace | 98 | 98 | 98 | 0 |

**Key observed weakness:** NAXSI detected **28/240 (11.67%)** double-encoded malicious-labelled requests, while ModSecurity detected **240/240**. Of NAXSI's 254 missed detections, **212** were double-encoded SQLi/XSS cases and **42** were baseline path-traversal cases. These results suggest an investigation into normalisation, decoding, scoring and rule coverage; the precise cause has **not** been independently isolated.

### Response timing

| Client-observed statistic | ModSecurity | NAXSI |
|---|---:|---:|
| Median | 8.6795 ms | 4.8400 ms |
| 95th percentile | 53.492 ms | 48.407 ms |

These are observed end-to-end request times for the saved run. They **do not isolate WAF overhead**, establish throughput/scalability, or support significance claims without equivalent repeated workloads.

### Figures

Consult `Final_Submission/Evidence/Results/` or `Final_Submission_Complete/Final_Analysis/Results/` for:

- `modsecurity_confusion_matrix.png` and `naxsi_confusion_matrix.png`
- `waf_performance_comparison.png`
- `attack_category_detection.png`
- `naxsi_fn_by_category.png` and `naxsi_fn_by_transformation.png`
- `transformation_detection_comparison.png`
- Associated `*.csv` datasets and `generate_figures.py`, `analyse_categories.py`, `analyse_transformations.py`

## 8. Evidence preservation, publishing and privacy

1. **Do not alter raw experiment CSVs, original audit logs or server logs.** Work from copies and write reviewed decisions separately.
2. Keep run identifiers, test identifiers, corpus hashes, configuration snapshots and review notes alongside summaries. Confirm which checksum list covers which files.
3. **Do not publish historical `test_config.json`, credentials, DVWA cookies, API tokens, authorization headers or unsanitized HTTP traces** to a public repository.
4. Use the team's approved GitHub project/branch for **reviewed, sanitized** artifacts. The user's clone was at `~/waf-github-evidence`, on branch `bishal-weekly-evidence`; cloning does not mean later files were pushed. Avoid force pushing or overwriting teammates' work.
5. Confirm the intended reviewer has access to the final ZIP or repository. No previous local archive check proves supervisor delivery.
6. Document exclusions and limitations rather than silently editing uncertain observations to match desired metrics.

## 9. Known limitations and troubleshooting

- **Environment:** NAT/host-only interface mixing can break package installation or lab routing. Verify `ip -br addr`, `ip route`, VirtualBox adapters and service listeners before testing.
- **Authentication:** An expired DVWA session can redirect a test to the login page; review authentication state and captured response rather than counting that as a valid attack disposition.
- **Enforcement:** `SecRuleEngine`, NAXSI rule thresholds and active Nginx includes must be checked. A ModSecurity `Message: Warning` line alone does not establish blocking.
- **Correlation:** Match **exact request IDs** between proxy and backend logs; don't infer from HTTP 200/403 alone.
- **Sample scope:** One reviewed run per configuration, related transformed cases, one vulnerable app and unequal real-world traffic prevalence limit generalisation.
- **Analysis scripts:** Some scripts use original absolute paths or write output into result directories. Inspect source first and reproduce on a working copy.
- **Plot dependencies:** If `matplotlib`/`numpy` are missing, inspect internet/NAT access and install into the virtual environment only when authorised; existing CSV/JSON summaries remain readable without plotting packages.
- **VM clipboard:** Historical VirtualBox clipboard failures affected convenience, not the recorded WAF metrics. Restarting a VM is not evidence that a test configuration remained unchanged; reconfirm the network afterward.
- **Versioning:** Local files and hashes are preserved, but not every historical configuration change or a fresh clean-room restoration has been proven.

## 10. Scope boundaries and recommended next work

The work here documents **Bishal's ModSecurity/NAXSI Experiment A**. It does not subsume teammates' separate Coraza implementation, R11/R12 three-WAF evaluations, or unexecuted expanded-corpus v2 drafts. Their denominators, baselines and application-effect criteria must stay separate unless a verified matched protocol justifies comparison.

Recommended follow-up:

1. Isolate NAXSI double-encoding misses with controlled decode-depth/rule-threshold checks and independent benign controls.
2. Investigate the 42 path-traversal misses and the two WAFs' benign false positives with exact backend response evidence.
3. Repeat the evaluated workload with controlled application state and independently reproducible runner commands.
4. Benchmark equal-duration, matched authenticated traffic at multiple levels while recording throughput, errors, CPU and memory.
5. Verify XML injection and other server-side attack scope separately; do not claim those datasets were executed without evidence.
6. Test an extracted ZIP in a clean environment, recreate the lab from snapshots/configurations and record mismatches.
7. Complete a secret scan and publish a reviewer-safe set of evidence, documentation and linked figures.
8. Integrate all independently validated team results into the final thesis with individual attribution and methodological limitations.

## 11. For assessors and future students: quick review path

1. Read this README and `Week_07/docs/architecture.md`.
2. Inspect the two `metrics.json` files, then `Week_06/results/processed/comparison.csv`.
3. Inspect the actual input/variant CSVs and semantic-validation CSV.
4. Trace a representative NAXSI missed test (`SQLI_0090_DOUBLEENC`) to reviewed decisions and proxy/backend logs.
5. Open the supplied original figures and verify their counts against CSV/JSON outputs.
6. Check the evidence manifest and checksum list within their **stated scope**.
7. Review the documented limitations before interpreting detection results.

**Related assessment materials:** COMP6016 Progress Report 1 (individual scoping report, 9 August 2026); individual technical contribution report; consolidated Group 11 requirements record; Progress Report 3 handover. These are supporting documents, not substitutes for the original experiment logs and source code.

---

*Attribution note: This README describes the preserved ModSecurity/NAXSI workstream and its evidence. Script listings and configurations may include reused or jointly maintained project material. A file's presence does not by itself establish exclusive authorship. Coraza and separate controlled-experiment findings are attributed to the relevant team members in the group documentation.*
