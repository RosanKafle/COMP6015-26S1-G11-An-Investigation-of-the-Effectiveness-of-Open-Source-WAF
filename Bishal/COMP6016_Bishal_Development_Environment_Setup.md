# Development Environment and Reproduction Guide

**COMP6016 — An Investigation of the Effectiveness of Open-Source Web Application Firewalls**  
**Workstream:** ModSecurity and NAXSI | **Contributor:** Bishal Giri (22902243)  
**Supervisor:** Mihai Lazarescu | **Group:** 11 | **Prepared:** 25 October 2026

> **Reproduction status:** The archived project and its reviewed analysis have been demonstrated in the original Kali environment. A clean installation of both live WAF conditions from this handover has **not** been independently verified. This document distinguishes (A) reproducing calculations from saved data from (B) reconstructing the live VM laboratory. It is not a turnkey Docker image, and no Docker image for this WAF workstream has been established.

## 1. Scope and architecture

The laboratory compared two *alternative* WAF protection conditions against the same deliberately vulnerable DVWA application:

```text
                       VIRTUALBOX LABORATORY
              Kali Linux (HTTP testing + Python analysis)
                            |
                   host-only virtual network
                            |
                +-----------+-----------+
                |                       |
       Condition A: ModSecurity   Condition B: NAXSI
         Apache + OWASP CRS        Nginx + NAXSI
                |                       |
                |                 reverse proxy
                |                       |
                +-----------+-----------+
                            |
                     Apache / DVWA
                       Ubuntu VM
```

The WAF conditions were run as separate experimental conditions, **not** as simultaneously enforced layers. The saved NAXSI logs identify historical client `192.168.56.100`, target `192.168.56.20`, and Apache backend local port `8080`. These values are evidence from a past run; do **not** assume they remain valid on another host or VM.

**Required components for full live reconstruction:** Oracle VirtualBox; Kali Linux; Ubuntu; Apache; PHP/database dependencies required by the deployed DVWA; ModSecurity with OWASP CRS; Nginx with a working NAXSI module and rules; Python 3 with the project dependencies; approved isolated networking. The historical configuration snapshots are in the log/configuration directories below. Specific OS/package versions, database credentials and all service-install commands must be verified against the actual snapshots before rebuilding; they are not established by the currently available handover.

## 2. Folder structure and handover files

The *original* workspace was `/home/bishal/waf-semester2`. Development folders `Week_01` through `Week_07` were present; later summaries are under the final-analysis folders rather than fictional `Week_08`–`Week_13` directories.

```text
waf-semester2/
  Week_01/ ... Week_04/              earlier project development
  Week_05/                           clean baseline runs and configuration evidence
  Week_06/
    config/test_config.json
    requirements.txt
    scripts/                       request execution and evidence processing
    test_cases/                    normal + attack-labelled cases
    test_cases/variants/generated_variants.csv
    outputs/variant_semantic_validation.csv
    results/raw/                   ORIGINAL evidence: do not edit
    results/processed/             reviewed decisions + comparison.csv
    logs/week06-modsecurity-clean/
    logs/week06-naxsi-clean/
  Week_07/
    analysis/                      metrics, categories, latency, merge scripts
    results/processed/
  Final_Submission/Evidence/Results/      final CSV analysis + figures
  Final_Submission/Evidence/Logs/         preserved configurations/logs
  Final_Submission/evidence_manifest.csv
  Final_Submission_Complete/
    Project/Week_01/ ... Week_07/
    Final_Analysis/Results/
    Final_Analysis/Logs/
```

If using the expanded ZIP `COMP6016_Group11_BishalGiri_Complete_Code_Data.zip`, the root after extraction is `Final_Submission_Complete/`, **not** `waf-semester2/`. Some Python scripts may embed the historical workspace path. Run them on a working copy and inspect `--help` / the source before invoking them.

## 3. Path A — Reproduce results *offline* (recommended first)

This path does **not** require running Ubuntu, DVWA, Nginx or new attack traffic. It checks that the saved experiment inputs and calculations are accessible.

### 3.1 On KALI: inspect prerequisites

```bash
cd ~/waf-semester2
python3 --version
ls -l Week_06/requirements.txt
ls -l Week_06/results/processed/comparison.csv
ls -l Week_07/results/processed/modsecurity-week6/metrics.json
ls -l Week_07/results/processed/naxsi-week6/metrics.json
```

If using the *existing original VM* where `.venv` already exists:

```bash
source .venv/bin/activate
python -c 'import csv,json; print("Python standard library OK")'
```

If recreating a virtual environment on a **separate working copy** (requires compatible Python and internet or a local package cache):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r Week_06/requirements.txt
```

The original Kali VM previously installed `numpy` and `matplotlib` successfully for final charts. Those imports are only needed for plotting scripts, not for the basic saved-JSON checks.

### 3.2 On KALI: validate saved results without modifying files

```bash
python - <<'PY'
import json
from pathlib import Path
for waf in ('modsecurity', 'naxsi'):
    p=Path(f'Week_07/results/processed/{waf}-week6/metrics.json')
    d=json.loads(p.read_text())
    print(waf.upper(), {k: d.get(k) for k in
        ('TP','TN','FP','FN','UNKNOWN','total_rows','errors','skipped')})
PY
```

Expected stored reviewed counts:

| Outcome | ModSecurity | NAXSI |
|---|---:|---:|
| Total requests per WAF | 1,684 | 1,684 |
| True positives (TP) | 1,564 | 1,310 |
| True negatives (TN) | 109 | 108 |
| False positives (FP) | 11 | 12 |
| False negatives (FN) | 0 | 254 |
| UNKNOWN, errors, skipped | 0 | 0 |

For independent validation of the merged result file:

```bash
python - <<'PY'
import csv
from collections import Counter
p='Week_06/results/processed/comparison.csv'
with open(p, newline='', encoding='utf-8-sig') as f:
    rows=list(csv.DictReader(f))
print('Matched rows:',len(rows))
for col in ('modsecurity_classification','naxsi_classification'):
    print(col,dict(Counter(x[col] for x in rows)))
PY
```

Expected: 1,684 matched rows, and the TP/TN/FP/FN counts above for each classification column. If a file differs, investigate the file version and run provenance rather than altering the raw data.

### 3.3 On KALI: inspect scripts and perform an optional controlled offline rerun

```bash
ls Week_07/analysis/
python Week_07/analysis/metrics.py --help
python Week_07/analysis/merge_results.py --help
```

**Do not assume** the scripts accept `--input` or other flags until `--help` or the source confirms the interface. Some scripts may write files by default; configure output paths to a separate directory such as `~/waf-semester2/demo_outputs/`, not `results/raw/`. The preserved `metrics.json`, `comparison.csv` and generated PNGs are already usable evidence even if a particular script lacks a standalone CLI.

### 3.4 On KALI: examine the actual input corpus

```bash
ls -lh Week_06/test_cases/
head -n 4 Week_06/test_cases/variants/generated_variants.csv
head -n 4 Week_06/outputs/variant_semantic_validation.csv
```

The complete matched corpus has 600 baseline requests plus 1,084 generated variants across normal and attack-labelled cases. Four malicious categories were evaluated: SQL injection, XSS, command injection and path traversal. Variant labels include case, comments, encoding, double encoding, separators, URL encoding and whitespace. See the CSV for **exact** payload text; do not substitute illustrative payloads for recorded requests.

## 4. Path B — Restore and verify the live laboratory (conditional, not yet clean-room validated)

**Before starting:** Work only on the authorised, isolated university DVWA laboratory. Do not run active tests until confirming the VM network, effective WAF configuration, and target. An enabled NAT adapter on Kali can be used for package installation but does not establish that the deliberately vulnerable application is isolated.

### 4.1 VirtualBox host configuration (Windows host)

- Retain a host-only adapter for Kali–Ubuntu traffic; connect both machines to the **same** host-only network.
- Optional Kali NAT adapter may be used for software installation. Check routes afterward.
- Confirm the vulnerable Ubuntu services are **not bridged or publicly forwarded** unless explicitly approved.
- Record VM names, adapter settings and a snapshot before configuration changes.

### 4.2 On KALI — client verification

```bash
ip -br addr
ip route
python3 --version
```

Determine the target IP from the *current* Ubuntu address, not the saved historical `192.168.56.20`. When an authorised target is verified, a basic connectivity check may be made with `ping -c 3 <CURRENT_UBUNTU_IP>`; ICMP can be blocked, so also verify the permitted application endpoint. Verify whether the Python runner authenticates to DVWA and its configured target before using live execution options.

### 4.3 On UBUNTU — service and configuration verification

```bash
ip -br addr
sudo ss -lntp
sudo apache2ctl -t
sudo systemctl status apache2 --no-pager
sudo nginx -t
sudo systemctl status nginx --no-pager
```

The Nginx checks apply to the NAXSI condition; `nginx` might not be active in the ModSecurity condition. Verify the effective configuration using:

```bash
sudo nginx -T
sudo apache2ctl -M
```

`nginx -T` and `apache2ctl -M` may display long or sensitive configuration output. Save only authorised, sanitized copies. Check that the NAXSI module is loaded and the intended rule files are included; for ModSecurity, inspect `SecRuleEngine` and CRS inclusion. **Stored configuration files do not prove that they are currently loaded.** Ensure that a second enforcing ModSecurity layer does not accidentally confound the NAXSI results.

### 4.4 On KALI — locate the historical configuration snapshots

```bash
ls Week_06/logs/week06-modsecurity-clean/
ls Week_06/logs/week06-naxsi-clean/
grep -n 'SecRuleEngine' Week_06/logs/week06-modsecurity-clean/modsecurity.conf
```

Expected saved evidence includes `modsecurity.conf`, `000-default.conf`, `modsecurity-audit.log`, `naxsi-site.conf`, `naxsi.rules`, `naxsi_core.rules`, `nginx-config.txt`, `naxsi-access.log`, `naxsi-error.log` and `apache-backend.log`.

The provided handover is **not** an independently tested installation script for Apache, DVWA, CRS or NAXSI. Rebuilding requires checking module availability, Ubuntu/PHP/database compatibility, configuration include paths, and credentials on the target VM. Document all deviations from the historical snapshot in a new run directory before comparing results.

## 5. Request execution and WAF evidence workflow

```text
Input CSV + test_config.json
           ↓
Python test loader / DVWA session / request runner
           ↓
CURRENT verified WAF condition (ModSecurity OR NAXSI)
           ↓
WAF audit or proxy-access/error logs + Apache backend log
           ↓
Evidence review keyed by test ID / run ID / request ID
           ↓
Reviewed decision CSVs, keeping ambiguous/error/skipped UNKNOWN
           ↓
Matched comparison.csv → metrics.json → charts
```

Important scripts (inspect actual CLI before execution): `Week_06/scripts/run_test_set.py`, `request_runner.py`, `dvwa_session.py`, `parse_modsecurity_audit.py`, `apply_evidence.py`, and `Week_07/analysis/metrics.py`, `merge_results.py`, `category_summary.py`.

**Classification policy:** Do not infer a firewall `BLOCKED` action only from HTTP 403, or `ALLOWED` only from HTTP 200. Use ModSecurity audit records / NAXSI rule and proxy evidence plus backend request correlation. Keep unverified, errored or skipped cases UNKNOWN or unreviewed; preserve original raw CSV files unchanged.

## 6. Data provenance, integrity and privacy

Saved run examples:

| Condition | Run ID |
|---|---|
| ModSecurity clean baseline | `20260921T155000Z_d194f19db17d` |
| NAXSI clean baseline | `20260921T164645Z_a1ab5dc9e495` |
| ModSecurity reviewed experiment | `20260922T081541Z_d78b12c20b69` |
| NAXSI reviewed experiment | `20260922T084234Z_e864a464e30f` |

On **KALI**, verify the copied evidence hashes if the manifest matches the extracted path structure:

```bash
cd ~/waf-semester2
sha256sum -c Final_Submission/Evidence/Logs/evidence_sha256.txt
```

The historical screenshot showed successful checks for the copied log/config evidence. Inspect `Final_Submission/evidence_manifest.csv` for additional file-level hashes and scope; do not interpret a successful check of some files as verification of the complete project ZIP.

Before publishing any data to the team's GitHub repository, review request bodies, logs, configuration files and CSVs for authentication values, passwords, tokens, cookies and personal data. Only upload approved sanitized evidence. Raw logs may contain sessions and must not be exposed just because they are from DVWA.

## 7. Saved results and how to interpret them

- **ModSecurity:** TP 1,564; TN 109; FP 11; FN 0. Reviewed malicious recall: 100%; false-positive rate on 120 normal cases: 9.17%.
- **NAXSI:** TP 1,310; TN 108; FP 12; FN 254. Reviewed malicious recall: 83.76%; false-positive rate: 10.00%.
- **NAXSI misses:** 212 double-encoded requests (120 XSS and 92 SQLi), plus 42 baseline path-traversal requests. NAXSI detected only 28/240 double-encoded malicious-labelled requests in the reviewed dataset.
- **Client-observed response times:** median ModSecurity 8.6795 ms vs NAXSI 4.8400 ms; p95 53.492 vs 48.407 ms. These are *end-to-end observations*, not isolated WAF overhead.

The results apply to **specific configurations and the saved matched corpus**, not to every installation of either product. An attack-labelled request that reached Apache was an operational WAF miss; it was not necessarily a successful exploit.

## 8. Troubleshooting and handover notes

| Problem | Check first | Safe next action |
|---|---|---|
| Kali has no internet | `ip route`; VirtualBox NAT attachment | Restore/check NAT and DHCP only on the intended adapter; don't change host-only test topology blindly |
| Kali cannot contact Ubuntu | IP/subnet on both VMs, host-only adapter name, listeners | Confirm target/service state before further tests |
| `ModuleNotFoundError` | Active `.venv`, `python -m pip list` | Install pinned/required dependencies in a fresh venv |
| Logs do not show expected events | Current WAF rule engine, audit/access logging, proxy-to-backend route | Confirm effective configuration and request ID propagation |
| WAF status differs from expected | DVWA session/security level, rule thresholds, app redirects | Investigate configuration and evidence; never overwrite past results |
| Charts cannot be generated | matplotlib/numpy and hardcoded paths | Run on working copy with verified imports and path changes |
| Clipboard fails in VirtualBox | Guest Additions/host clipboard state | Do not modify the experiment data to repair clipboard; use separate troubleshooting procedures |

## 9. Known limitations and future work

A clean-room redeployment and full fresh replay of both WAF conditions remain to be demonstrated. The saved experiments cover SQLi, XSS, command injection, path traversal and selected transformations; XML injection and additional server-side categories proposed in the initial scope are not established by this saved workstream. Complete active network-isolation verification, controlled rule-tuning regression, repeated load tests, resource measurements and additional application-level exploit-effect validation are also worthwhile next steps. Coraza and the group's R11/R12 experiments are separate workstreams; their figures must not be pooled with this 1,684-case pair without an explicit common methodology.

## 10. Reviewer acceptance checklist

- [ ] Access the source scripts, input CSVs, config snapshots, raw and reviewed outputs.
- [ ] Confirm that the saved merged dataset has 1,684 matched rows.
- [ ] Confirm the TP/TN/FP/FN totals from both saved metrics files.
- [ ] Identify the 254 reviewed NAXSI misses and the double-encoding concentration.
- [ ] Inspect the WAF audit / NAXSI proxy and Apache backend log evidence.
- [ ] Verify the recorded SHA-256 checks for the files within each manifest's scope.
- [ ] Confirm all target URLs and paths if attempting a new deployment.
- [ ] Preserve raw evidence unchanged and send derived outputs to new locations.
- [ ] Sanitize files before external GitHub sharing.

**Companion documentation:** `README_Bishal_WAF_Semester2.md`, `Week_07/docs/architecture.md`, `Week_06/requirements.txt`, the scripts and configurations above, and the verified group Requirements Form.
