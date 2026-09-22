# Review of Third Semester work

This records the original folder review. The subsequently supplied final report and
its 600-row detail file are now the continuation baseline. See continuity_mapping.md
and historical/final_report/source_manifest.json for the additional evidence.

## What I understand

The project moved from broad ZAP scanning of DVWA to category-specific replay,
mixed normal/malicious traffic and a larger payload-level XSS investigation. Your
infrastructure role connects the traffic generator, authenticated target application,
WAF deployment/mode, request automation and server-side evidence. The continuation
should improve experimental control and interpretation of misses, not restart the
research question.

The supplied material describes Kali/DFIR01 as the traffic generator, an Ubuntu lab
server, DVWA under /DVWA/, Apache/ModSecurity with OWASP CRS and Nginx/NAXSI.
It reports ZAP 2.17.0 and CRS 3.3.7. These are historical descriptions and screenshots,
not verified current installations. The later NAXSI report describes Nginx on port 80
and Apache/DVWA moved to backend port 8080; it also discusses correcting learning-mode
and proxy/session issues. This needs a fresh topology and mode check before new tests.

## Scope of this review

The original directory contains 231 files with 166 unique SHA-256 contents:
38 Python files, 73 CSVs, 10 JSONs, 70 PNGs, 23 text files, 7 DOCX entries
(including one Word lock file), 6 CSS files, 3 Markdown files and one HTML report.
The six substantive Word files were text-extracted; the lock file is not a report.
All files were inventoried and hashed, Python sources parsed, and CSV/JSON structure
inspected. The 68 substantive screenshots were surveyed in contact sheets, with a
full-resolution check of the ModSecurity enablement screenshot; the other two PNGs
are ZAP icons. This is a content review, not forensic authentication of screenshots
or independent reproduction of the experiments.

See source_inventory.csv for every original file, its hash and available structural
counts. No original source or result file was changed or executed.

## Source groups and progression

| Source relative to Third Semester work | What it contains |
|---|---|
| WAF Ongoing/WAF_Effectiveness_Project_Report.md and .docx | Early consolidated report, environment, ZAP methodology and limitations |
| WAF Ongoing/zap-waf-framework/ | Earlier automation/traffic/results snapshot |
| zap-waf-framework/ | Superset including later XSS datasets, replay and NAXSI results |
| WAF Ongoing/Manual Baseline Test/ | Normal capture, SQLi generation/replay and screenshot evidence |
| WAF Ongoing/Using ZAP for Custom attacks (Mod Security)/ | Mixed/scanner experiments and output screenshots |
| WAF Ongoing/Python Automation Tested before master script/ | ZAP API setup, initial automation and classification explanations |
| WAF Ongoing/ZAP on DVWA Security Low NAXII NGINX/ | ZAP HTML report, alerts and screenshots |
| Final Test of XSS with custom XSS payload for ModSecurity/ | Later XSS screenshots, Prem Report.docx and drafting prompts |
| Final Test of XSS with NASXII/ | NAXSI report, configuration and result screenshots |

The two framework folders share 58 file paths with byte-identical contents.
The top-level framework adds the later work, so treating both copies as independent
experiments would double-count evidence. Drafting prompts inside Word files are
planning material, not experimental evidence.

## Findings recorded in the supplied data

The starter XSS dataset has 150 rows; another research dataset has 272 rows; the
large shared dataset has 1,774 rows. Each later per-WAF detailed XSS CSV also has
1,774 rows. The saved missed-payload CSVs contain 105 ModSecurity rows and 16 NAXSI rows.

| Historical summary file under zap-waf-framework/results/xss/ | Total | Reported blocked | Reported missed/allowed | Saved detection-rate label |
|---|---:|---:|---:|---:|
| xss_payload_summary_modsecurity.csv | 1,774 | 1,669 | 105 | 94.08% |
| xss_payload_summary_naxsi.csv | 1,774 | 1,758 | 16 | 99.1% |

These figures are read from existing files, not newly measured results. Both replay
scripts infer disposition primarily from response status. The comparison therefore
supports an investigation of recorded response behaviour, but does not by itself
prove equivalent configurations, successful exploitation of every allowed payload,
or a general superiority claim about either WAF.

Earlier scanner and mixed exports use different cohorts. For example, the stored
ModSecurity and NAXSI mixed-traffic detail files contain 78 and 109 rows respectively.
The earlier report's screenshot totals and saved scanner CSV counts also vary across
runs. Do not combine these as one matched experiment.

## Issues to address in the continuation

1. **The early report is incomplete relative to the later files.** It says NAXSI
   numerical results and normal traffic were outstanding. Later NAXSI XSS results,
   normal-traffic JSONs and mixed-traffic files are present. The final account should
   distinguish stages and source artifacts explicitly.
2. **Status-only classification needs refinement.** xss_payload_replay_modsecurity.py
   and test_naxsi_xss_payloads.py treat 403/406 as blocked and 200 as allowed. Other
   mixed runners use broader status sets. A common decision protocol is needed.
3. **WAF and application controls matter.** The ModSecurity screenshot shows
   security2_module and SecRuleEngine On. That supports enablement at capture time,
   not every later transaction. NAXSI learning/enforcement state, DVWA security level,
   sessions and the reverse-proxy path need equivalent run evidence.
4. **Raw rule logs are missing from this supplied folder.** References and screenshots
   mention audit/access logs, but no .log files were supplied. Aggregate rule-hit
   counters cannot reliably identify which rule blocked a specific request.
5. **Dataset validity is unresolved.** The NAXSI report itself discusses possible
   Markdown/explanatory-text noise and non-executable misses. An allowed string
   labelled XSS is not automatically a working XSS exploit. Review parent payloads
   and browser/application context before interpreting missed detection.
6. **XSS-only matrices lack the normal class.** The later one-row XSS confusion
   matrices cannot establish normal-traffic false-positive rates. Earlier mixed
   traffic exists but must be evaluated as its own labelled and controlled cohort.
7. **Reproducibility and secrets need cleanup in new code.** Legacy scripts contain
   hard-coded target/session settings and different request/proxy conventions.
   New work uses configuration, private environment secrets, immutable collection
   and a stable corpus digest; no legacy credentials were copied into the new repo.

## How Weeks 1–7 build on this

Week 1 documents and re-verifies the inherited architecture. Week 2 makes the
experimental decisions explicit. Week 3 now freezes the inherited 600-row mixed workload with traceable templates.
Explicit smaller pilot runs remain available. Week 4 collects requests and evidence without
status-derived assumptions. Week 5 controls corpus equivalence across WAFs.
Week 6 tracks baseline-to-variant lineage and semantic review. Week 7 analyses only
actual supplied observations, preserving unknowns and separating errors/skips.

The supplied weekly milestone specification was used to organise these snapshots.
No separate Semester 4 weekly reports were found in the supplied folder; the folder
names do not assert that this work was historically completed during those weeks.
