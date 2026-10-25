# COMP6016 — Data Management and Evidence Handover

**Project:** An Investigation of the Effectiveness of Open-Source Web Application Firewalls  
**Workstream:** ModSecurity (OWASP CRS) and NAXSI comparative evaluation  
**Contributor:** Bishal Giri (22902243), Group 11  
**Supervisor:** Mihai Lazarescu  
**Date:** 25 October 2026

> **Scope:** This guide inventories Bishal's preserved ModSecurity/NAXSI data. The group also has separate Coraza, R11/R12, and expanded-corpus evidence; those collections are not included in the 1,684-case totals and must be indexed separately by their owners. File paths below are relative to `~/waf-semester2/` on Kali unless stated otherwise. The archive was observed to contain Weeks 01–07 and later `Final_Analysis` outputs; there were no distinct `Week_08`–`Week_13` directories in the checked project tree.

## 1. Purpose and data lifecycle

The dataset supports controlled comparison of WAF *dispositions*—whether a labelled malicious request was blocked or allowed, and whether a normal-labelled request was allowed or blocked. It does **not** automatically establish that an allowed payload exploited DVWA. Each conclusion should be traceable through this chain:

`source test cases → variant generation/validation → WAF-specific run (run_id, test_id) → raw HTTP outcomes + WAF/backend logs → reviewed decision → matched comparison → metrics and figures → final report`

**Preservation rule:** Do not modify raw test results, logs or original payload CSVs in place. Keep a read-only original, make working copies for analysis and write review decisions and charts to separate directories. Do not conflate a status code (such as 200 or 403) with a WAF action unless supporting evidence exists.

## 2. Project directory and access map

| Data type | Recorded path / location | Why it matters |
|---|---|---|
| Original development history | `Week_01/` through `Week_07/` | Scripts, settings, input cases, logs and historical outputs |
| Input attack and normal CSVs | `Week_06/test_cases/` | Original labelled cases for SQLi, XSS, command injection, traversal and normal requests |
| Generated obfuscated inputs | `Week_06/test_cases/variants/generated_variants.csv` | Generated payload versions, test IDs and transformations |
| Variant validation | `Week_06/outputs/variant_semantic_validation.csv` | Recorded validation status for generated cases; not proof of semantic equivalence for every backend |
| Recorded run settings | `Week_06/config/test_config.json`, `Week_06/results/raw/**/test_set.json` | Run parameters and exact saved test set; inspect actual run directory before use |
| Immutable raw run output | `Week_06/results/raw/` | WAF-specific original request outcomes and run IDs |
| Human-reviewed decisions | `Week_06/results/processed/modsecurity-reviewed-decisions.csv`, `Week_06/results/processed/naxsi-reviewed-decisions.csv` | Separately reviewed WAF action labels |
| Matched pair-level comparison | `Week_06/results/processed/comparison.csv` | Aligned test IDs, categories, variants and both WAF classifications |
| ModSecurity evidence | `Week_06/logs/week06-modsecurity-clean/` | Apache requests, ModSecurity audit log, site/module/config and listener records |
| NAXSI evidence | `Week_06/logs/week06-naxsi-clean/` | Nginx access/error, Apache backend log, rules, site config, effective config and listener records |
| Audit-review intermediates | `Week_06/results/processed/modsecurity-audit-review/` | Rule events, block candidates and validation subsets |
| Result summaries | `Week_07/results/processed/modsecurity-week6/`, `Week_07/results/processed/naxsi-week6/` | `metrics.json`, `confusion.csv`, categories, missed detections, latency outputs |
| Comparison / figure data | `Final_Submission/Evidence/Results/` | Tables, plotted figures and analysis scripts |
| Complete handover working copy | `Final_Submission_Complete/Project/`, `Final_Submission_Complete/Final_Analysis/` | Archived weekly inputs and subsequent consolidated analysis |
| Integrity evidence | `Final_Submission/Evidence/Logs/evidence_sha256.txt`, `Final_Submission/evidence_manifest.csv` | Checksums and provenance of copied evidence files |

Paths are based on preserved project inventory and screenshots; use the inventory commands below to identify the precise run-specific filename. Folder presence does not by itself prove a complete clean rebuild.

## 3. Experiment populations and lineage

**Experiment A (this workstream):** 1,684 matched labelled requests **per WAF**, or 3,368 WAF observations. Per WAF there were 120 normal-labelled and 1,564 malicious-labelled requests. The corpus was reported as 600 baseline records plus 1,084 generated variants. A matched corpus means the test IDs/cases were aligned; it does not imply identical WAF engines, rulesets or backends in every respect.

**Historical run references:**

- Week 5 clean ModSecurity baseline: `20260921T155000Z_d194f19db17d`.
- Week 5 clean NAXSI baseline: `20260921T164645Z_a1ab5dc9e495`.
- Reviewed ModSecurity extended run: `20260922T081541Z_d78b12c20b69`.
- Reviewed NAXSI extended run: `20260922T084234Z_e864a464e30f`.
- The originally matched Week 5 baseline corpus SHA-256 was recorded as `d93261a134549f8ac08935d013df2161dacc7acaaabb9072524ccf00bf946be7`. Verify which exact corpus file this applies to before using it as an integrity assertion for any different input.

**Do not pool** this dataset with the team's independent three-WAF R11/R12 testing, historical automated tests, or expanded-corpus v2 offline fixtures. Those use different denominators, inclusion criteria or states of validation.

## 4. Data dictionary — essential fields

The following fields have been observed across reviewed/result CSVs; not every file has every column. Use each CSV's header as the source of truth.

| Field | Meaning / interpretation |
|---|---|
| `run_id` | Identifies a particular execution; distinguishes tests repeated at different times |
| `test_id` | Stable identifier for a test case, e.g. `SQLI_0090_DOUBLEENC` |
| `parent_test_id` | Original case from which a variant was generated, where present |
| `category` | Attack family, e.g. `sqli`, `xss`, `command_injection`, `path_traversal` |
| `variant` / `transformation` | Baseline or obfuscation family, e.g. `doubleenc` |
| `payload` | Actual recorded input string; must be quoted/encoded carefully and reviewed for sensitive content |
| `http_status` | HTTP response status **not sufficient** to establish firewall action |
| `waf_action` | Reviewed disposition, e.g. `BLOCKED`, `ALLOWED`, `UNKNOWN` |
| `notes` | Analyst review, log references and limits |
| `modsecurity_action` / `naxsi_action` | Corresponding reviewed WAF decisions in matched comparison |
| `modsecurity_classification` / `naxsi_classification` | TP, TN, FP, FN (or other unreviewed states when applicable) |
| `response_time_seconds` | Client-observed response time; not isolated WAF overhead |
| `rid` / `X-Lab-Request-ID` | Correlation identifier across Nginx and Apache logs when present |

In the comparison CSV observed columns include `test_id`, `category`, `variant`, both WAF actions and both classifications. Consult the actual file header before writing scripts.

## 5. Raw, reviewed and derived outputs — keep separate

1. **Input data:** Original malicious and benign cases plus transformed variants. These define the intended test labels and should retain test IDs and encoding exactly as submitted.
2. **Raw observations:** Execution-time request results, response metadata and WAF/backend logs; preserve as immutable evidence.
3. **Review intermediates:** ModSecurity `rule_events.csv`, `block_candidates.csv`, `non_block_candidates.csv`, `verified_block_candidates.csv` and related tables are aids for evidence inspection, **not automatic definitive WAF actions**.
4. **Reviewed decisions:** Manually supported WAF actions and reasons. If request evidence is incomplete or execution failed/skipped, leave `UNKNOWN`/unreviewed rather than guessing.
5. **Joined comparison:** Pair ModSecurity and NAXSI results by test ID and check unmatched IDs before creating aggregate tables.
6. **Derived outputs:** Confusion matrices, metrics JSON, category and transformation CSVs, latency summaries, charts, report text.

## 6. Verified classification results

| Metric | ModSecurity | NAXSI |
|---|---:|---:|
| Total observations | 1,684 | 1,684 |
| True positive (malicious blocked) | 1,564 | 1,310 |
| True negative (normal allowed) | 109 | 108 |
| False positive (normal blocked) | 11 | 12 |
| False negative (malicious allowed) | 0 | 254 |
| Unknown / error / skipped in reviewed dataset | 0 | 0 |
| Precision | 99.30% | 99.09% |
| Recall | 100.00% | 83.76% |
| F1 | 99.65% | 90.78% |
| Accuracy | 99.35% | 84.20% |

NAXSI false negatives reconcile to **120 XSS + 92 SQLi + 42 path traversal = 254**. By transformation: **212 double-encoded + 42 baseline = 254**. Of 240 malicious double-encoded requests, ModSecurity blocked 240; NAXSI blocked 28 (11.67% recall). These are observed WAF-disposition results in the tested configuration, **not proof** of 254 successful exploits.

Recorded median client times were 8.6795 ms (ModSecurity) and 4.8400 ms (NAXSI), with p95 53.492 ms and 48.407 ms respectively. These include application and networking effects and are not isolated overhead benchmarks.

## 7. How to inspect the data (read-only, KALI)

First navigate to the saved project:

```bash
cd ~/waf-semester2
source .venv/bin/activate
```

List the inputs and existing outputs:

```bash
find Week_06/test_cases -maxdepth 3 -type f | sort
find Week_06/results/raw -maxdepth 4 -type f | sort | head -n 60
find Week_06/results/processed Week_07/results/processed -type f | sort | head -n 100
find Final_Submission/Evidence/Results -maxdepth 1 -type f | sort
```

Read the CSV column names and row counts without changing files:

```bash
python - <<'PY'
import csv
from pathlib import Path
for p in [
    Path('Week_06/test_cases/variants/generated_variants.csv'),
    Path('Week_06/outputs/variant_semantic_validation.csv'),
    Path('Week_06/results/processed/comparison.csv'),
    Path('Week_07/results/processed/naxsi-week6/missed_detections.csv'),
]:
    if not p.is_file():
        print('MISSING:', p)
        continue
    with p.open(newline='', encoding='utf-8-sig') as f:
        reader=csv.DictReader(f)
        n=sum(1 for _ in reader)
        print(f'\n{p}\nrows={n}\ncolumns={reader.fieldnames}')
PY
```

Check saved metrics:

```bash
python - <<'PY'
import json
from pathlib import Path
for waf in ('modsecurity','naxsi'):
    p=Path(f'Week_07/results/processed/{waf}-week6/metrics.json')
    if p.exists():
        d=json.loads(p.read_text())
        print(waf, {k:d.get(k) for k in ('TP','TN','FP','FN','UNKNOWN','total_rows')})
    else:
        print('MISSING:', p)
PY
```

Identify files for one recorded test ID without printing private payloads:

```bash
grep -lF 'SQLI_0090_DOUBLEENC' Week_07/results/processed/naxsi-week6/missed_detections.csv Week_06/results/processed/comparison.csv
```

To correlate a specific request to proxy/backend evidence, obtain its **actual** `rid` from the saved record/log, then find that *same* value in both Nginx and Apache logs. Do not assume consecutive log rows belong to the same request.

## 8. Integrity, backups and file sharing

Historical log/config checksum verification on **KALI** (read only):

```bash
cd ~/waf-semester2
sha256sum -c Final_Submission/Evidence/Logs/evidence_sha256.txt
```

The prior verification showed 14 referenced ModSecurity/NAXSI log/config files as `OK`. That is evidence for the listed files only. A manifest of 31 evidence files was also prepared; an expanded archive requires its **own** integrity check and potentially regenerated manifest. For a ZIP archive, verify with `unzip -t FILE.zip` and inspect contents with `unzip -Z1 FILE.zip`.

- Maintain a protected source copy and a separate sanitized GitHub/share copy.
- Do not commit Git tokens, passwords, `.env` files, DVWA session cookies, raw Authorization headers or private credentials.
- Review request logs and configuration files for identifiers/secrets **before** sharing; hashing does not remove sensitive information.
- Store the original full archive in supervisor-approved storage with access limited to the team; share only approved/sanitized subsets publicly.
- Preserve SHA-256 manifests alongside the exact files they describe and record the date/source of each copy.
- Back up original datasets before reprocessing; never recalculate analyses by editing raw CSVs.

## 9. Verification and quality checklist

- [ ] Confirm `test_id` uniqueness and agreement of intended labels across the two WAF corpora.
- [ ] Confirm 1,684 reviewed rows per WAF and 120 normal / 1,564 malicious labels per WAF.
- [ ] Confirm TP+TN+FP+FN sums to 1,684 for each WAF.
- [ ] Confirm NAXSI FN breakdown sums to 254 by attack category **and** by transformation.
- [ ] Confirm zero unmatched test IDs in the paired comparison.
- [ ] Verify representative `rid` matches between NAXSI access and Apache backend logs.
- [ ] Confirm WAF action with rule/intervention evidence, not status alone.
- [ ] Mark any new ambiguous, skipped or failed cases UNKNOWN/unreviewed.
- [ ] Verify checksums and archive integrity for the exact set being handed over.
- [ ] Review sensitive information and access permissions before GitHub upload.
- [ ] Confirm a teammate can follow README and setup guide to reproduce **offline analysis** from supplied files.

## 10. Known limitations and future work

- The stored experiment supports descriptive comparison of the tested configurations only; related variants and single reviewed runs do not establish population-level statistical significance.
- The data does not prove backend exploitation for every passed malicious-labelled request.
- A complete clean-room rebuild and full live attack replay of the expanded handover ZIP were not independently verified.
- Response times include network/backend effects; controlled repeated throughput, concurrency and isolated WAF overhead tests remain future work.
- Investigate NAXSI's 212 double-encoded misses and 42 baseline traversal misses with controlled tuning experiments, preserving before/after configurations and matched cases.
- Extend documented test coverage to XML/server-side cases only when corresponding validated cases and run evidence exist.
- Coraza/R11/R12 and expanded corpus v2 belong in a **separate group-wide evidence index** with their own IDs, denominators, provenance and owner validation.

## 11. Related handover materials

- `README_Bishal_WAF_Semester2.md` — comprehensive project overview, code and results.
- `COMP6016_Bishal_Development_Environment_Setup.md` — setup and offline reproduction instructions.
- `Final_Submission_Complete/README.md` — the original assembled package overview.
- `Final_Submission/evidence_manifest.csv` — existing evidence inventory; scope-limited.
- Individual technical contribution report and reviewed group Requirements Form — assessment narrative and responsibility map.

**Handover standard:** A future researcher should be able to locate inputs, distinguish raw from reviewed results, identify exact experiment populations, validate calculations and inspect WAF/backend evidence without modifying the original files. If an environment or dataset cannot yet be reproduced, record that gap rather than inferring completion.
