# WORK_SYNC.md — cross-account continuity record

This file is maintained separately from the report/reviews. It records actual
dates, run IDs, commands, changes, evidence paths, validated findings,
unresolved points and next actions. Update after each meaningful step.

## 2026-09-22 — Account handover received and verified (this account)

- Received `WAF_ACCOUNT_HANDOVER_20260922.zip`. Verified all 8 members
  against `SHA256SUMS.txt` — all OK. No corruption or tampering detected.
- Read `START_HERE.md`, `analysis/WORK_SYNC_R11_REVIEW.md`,
  `analysis/WORK_SYNC_NAXSI_CONFIG_ADDENDUM.md` in full.
- Cross-checked `configuration/r11-naxsi-active-config.txt` directly:
  - Confirmed `SecRulesEnabled;` present, no `LearningMode`/`SecRulesDisabled`/
    whitelist directive in the snapshot.
  - Confirmed thresholds: `$SQL>=8`, `$RFI>=8`, `$TRAVERSAL>=4`, `$EVADE>=4`,
    `$XSS>=8` — matches both review docs exactly.
  - Confirmed rule bodies for ids 1000, 1005, 1006, 1007, 1008, 1009, 1013,
    1015, 1200, 1302, 1315 match the scores/attributions cited in the review
    and addendum (e.g. id:1008 semicolon → SQL:4,XSS:8; id:1006 `&&` →
    SQL:8; id:1005 `|` → SQL:8; id:1302 `<` → XSS:8; id:1315 `%[23].` double
    encoding → XSS:8).
  - Enumerated all 66 rule ids in the snapshot — none reference newline,
    printf, or an RCE-specific pattern. This is consistent with (does not
    prove beyond the snapshot) the "coverage gap" explanation for
    R11-CMD-E03 already stated in the addendum; it is not new evidence of a
    decoding failure and not a claim about other NAXSI deployments.
  - Listed both evidence tar.gz archives' contents (523 and 6 entries) without
    extracting raw request/response bodies — confirms archive structure
    matches what START_HERE.md describes (per-case `.request.json`/
    `.body.html` under `evidence/r11-*`, plus `results.jsonl`,
    `run_metadata.json`, runner scripts, and server-side logs/config dumps).
  - Loaded `analysis/correlation.json`: confirmed 225 list entries, first
    record `R11-BEN-SQL01`/modsec/rep1/control/sqli/HTTP200 — consistent
    with the stated 225 unique protected observations.
- No new HTTP requests were sent. No raw evidence was modified. No cleanup
  action was taken. No credentials were requested, printed or stored.

## Checkpoint confirmed (unchanged from handover)

- 225 protected R11 observations reviewed (189 attack + 36 control across
  ModSecurity/Coraza/NAXSI, 21 validated attack cases + 4 controls x 3 reps).
- One NAXSI command-injection miss (R11-CMD-E03, newline separator) is
  reproduced 3/3, attributed to a configuration coverage gap (no
  newline/printf-specific rule in the supplied NAXSI snapshot), NOT proven to
  be a URL-decoding failure and NOT generalised beyond this configured path.
- ModSecurity 63/63 and Coraza 63/63 attack blocks, 0/12 control false
  positives each. NAXSI 60/63 attack blocks (the one repeated miss), 3/12
  controls false-positive-blocked (3 distinct benign texts x3 reps).
- Three R11 candidates excluded at baseline (double-encoded, did not
  establish intended effect): R11-SQLI-E03, R11-XSS-E04, R11-PTH-E03. Not
  counted as WAF successes.
- Coraza numeric threshold / full config parity: NOT yet established.
- Live-origin XSS confirmation (vs. offline replay of saved bodies for 7
  cases): NOT yet done.
- XML/XXE testing: NOT executed (endpoint prerequisite missing).
- Representative benign/false-positive corpus: still a small purposive set
  (4 controls), not a population estimate.

## 2026-09-22 (continued) — R12 runner debugged, baseline validated, Coraza config parity resolved

### R12 script defect and fix (recorded here, not silently corrected)
- v1 of `r12_separator_encoding_runner.py` sent bare unauthenticated POSTs
  with no session. Result: 5 baseline runs between 07:08Z-07:11Z, all 8/8
  attack candidates failed the gate (0-byte HTTP 302 response bodies —
  redirected, not executed). These 5 directories
  (`evidence/r12-baseline-20260922T070829Z` through `...T071103Z`) are
  **invalidated script-defect runs, not real R12 data** — left on disk,
  not deleted, but must not be cited as results.
- Root cause found by reading R11's own proven runner
  (`run_corrected.py` imports `login`/`set_security_low` from
  `legacy_v10.py`): this DVWA instance requires an authenticated session
  AND an explicit `security=low` override (defaults to
  `security=impossible` post-login). v1 had neither.
- Fixed in v2 by importing and reusing `legacy_v10.login()` /
  `set_security_low()` unchanged inside a persistent `requests.Session()`.

### R12 baseline run — VALID (2026-09-22T07:31:07Z)
- Directory: `evidence/r12-baseline-20260922T073107Z`, 10 cases x 3 reps = 30
  observations, authenticated session confirmed.
- Gate result: 8/8 attack candidates PASSED (all four separators x both
  space encodings), benign control `R12-BEN-IP01` passed, the
  double-encoded negative control `R12-CMD-NEG-DBLENC` FAILED (did not
  produce the canary) — consistent with the R11 double-encoding exclusion
  pattern (R11-SQLI-E03/R11-XSS-E04/R11-PTH-E03).
- Gated case list for protected phase (9 cases): R12-CMD-SEMI-PCT,
  R12-CMD-SEMI-PLUS, R12-CMD-NL-PCT, R12-CMD-NL-PLUS, R12-CMD-AND-PCT,
  R12-CMD-AND-PLUS, R12-CMD-PIPE-PCT, R12-CMD-PIPE-PLUS, R12-BEN-IP01.

### UBUNTU prep — Section 0
- NAXSI instance re-confirmed identical to R11 (master PID 1859).
- Fresh NAXSI config snapshot taken; substantive lines byte-identical to
  R11 handover config. Raw file hash differs (formatting only, not a rule
  change) — recorded, not waved away.
- Coraza config parity RESOLVED: `tx.inbound_anomaly_score_threshold = 5`,
  matches ModSecurity's confirmed threshold (5).
- Apache/ModSecurity/CRS config parity RESOLVED: same thresholds (5/4,
  paranoia level 1) found in CRS package REQUEST-901-INITIALIZATION.conf.
  Full ModSecurity/Coraza config parity now evidence-backed.
- NAXSI correlation gap RESOLVED: extended live log_format to capture
  run_id/repetition headers; verified with a non-test curl request.
- **NOTE (this copy): the config snapshot files themselves
  (r12-coraza-crs-setup-*.txt, r12-apache-vhosts-*.txt,
  r12-modsec-crs-config-*.tar.gz, r12-modsec-crs-901-init-*.conf,
  r12-naxsi-nginx-conf-BACKUP-*.conf) are saved on UBUNTU and have NOT yet
  been transferred into this repo/evidence tree — pending transfer, not
  missing evidence.**

### R12 protected run — VALID, FULLY CORROBORATED (run_id r12-20260922T073114Z-7220d26c)
- Directory: `evidence/r12-baseline-20260922T073107Z/protected_manifest.jsonl`
  (baseline and protected phases share this directory).
- 9 gated cases x 3 WAFs x 3 reps = 81 observations.
  - ModSecurity: 8/8 attack cases blocked, 3/3 reps each.
  - Coraza: 8/8 attack cases blocked, 3/3 reps each.
  - NAXSI: 6/8 blocked, 2/8 missed — exactly R12-CMD-NL-PCT and
    R12-CMD-NL-PLUS (newline separator, both space encodings), 3/3 reps
    each = 6/6 consistent HTTP 200 with confirmed command effect.
  - Benign control accepted (HTTP 200) by all three WAFs, no new false
    positive.
- **Finding: the R11-CMD-E03 NAXSI miss generalises specifically to the
  newline separator, independent of space encoding (%20 vs +), and does
  NOT generalise to semicolon/AND/pipe** (all reliably blocked).
- Full corroboration chain: client response body (genuine command output +
  canary), NAXSI access log (exact run_id/test_id/rep match, no
  chronological inference needed), and error log (no matching block event
  for any of the 6 miss naxsi_ids) all agree.

## 2026-09-22 (continued) — Git repo located, .venv cleaned, push plan drafted

### Repo identification
- Supervisor's actual shared repo:
  https://github.com/RosanKafle/COMP6015-26S1-G11-An-Investigation-of-the-Effectiveness-of-Open-Source-WAF.git
  (Group 11's repo; has a `comp6016-controlled-testing` branch used for
  current-semester work).
- Local branch `sadaiba-week5-ground-truth` (HEAD e0c6663) was never
  actually pushed to origin — confirmed. Nothing lost, just never left the
  local machine. Uncommitted local changes on that branch (modified
  `tools/controlled_validation/request_builder.py`, untracked evidence +
  `analysis/final_attack_type_summary.csv`) explicitly left untouched per
  user instruction.

### Read-only inventory of the old repo directory
- Before cleanup: 5183 files, 793 dirs, 142MB. `.venv/` was 3299 files/103MB,
  confirmed gitignored AND untracked — deleted with user approval. Directory
  now 41MB.
- Duplicate-hash analysis (excluding .venv/.git): 103 groups/442 files, most
  NOT redundant (identical WAF block-page bytes across reps = real repeated
  observations, or shared script/manifest templates reused across differently
  timestamped run attempts). No evidence directories deleted or recommended
  for deletion — needs a full directory-level comparison first.

## 2026-09-22 (continued) — R11/R12 pushed to a new branch off comp6016-controlled-testing

- `waf_corrected_v11/` (this directory) pushed as-is (minus `__pycache__`)
  into a new branch, to avoid touching the untouched `sadaiba-week5-ground-truth`
  uncommitted work. See branch name/commit in repo history.
- Includes: catalogue.json, legacy_v10.py, r12_separator_encoding_runner.py,
  README.md, run_corrected.py, run_protected.py, WORK_SYNC.md (this file),
  WORK_SYNC_PROTECTED.md, and the full evidence/ tree (R11 baseline/protected,
  all R12 baseline runs including the 5 invalidated v1 script-defect runs —
  kept for transparency, explicitly marked invalid above, not cited as
  results).
- Ubuntu-side config snapshots (Coraza/Apache/NAXSI) NOT yet included — see
  note above under "UBUNTU prep — Section 0".

## Unresolved / open items carried forward

- NAXSI raw config snapshot hash differs from R11's bundle despite identical
  substantive rule/threshold lines — cause not fully explained.
- Live-origin XSS confirmation, XML/XXE prerequisite, broader benign corpus,
  OWASP-tool cross-check, server-side exploit class: all still open.
- Ubuntu config snapshots for Coraza/Apache/NAXSI: captured on Ubuntu, not
  yet transferred into this repo — follow-up transfer + commit needed.
- Full directory-level comparison of `_previous_*`/`_attempt1_*` dirs in the
  old repo (COMP6015-26S1-G11-...) before any deletion decision: not done.

## Next actions

1. Transfer the Ubuntu config snapshots to Kali and add as a follow-up commit.
2. Do the full directory-level comparison of `_previous_*` dirs before any
   cleanup decision on the old repo.
3. Do not cite the five invalidated v1 baseline directories
   (070829Z-071103Z) as R12 data in any report or write-up.

## 2026-09-22 (continued) — Ubuntu config snapshots transferred; NAXSI hash mismatch resolved

- Transferred the 6 final Coraza/Apache/ModSecurity/NAXSI config snapshot
  files from Ubuntu to Kali and into this repo under `configuration_r12/`
  (previously only described in text, not present as files). File sizes on
  Kali match the Ubuntu originals exactly (byte-for-byte transfer, verified
  by `ls -la` on both sides).
- NAXSI raw-config hash mismatch (previously unexplained) RESOLVED:
  `r12-pre-naxsi-config-20260922T073528Z.txt` (266 lines, sha256
  `b115c50d...`) vs the R11 handover's
  `configuration/r11-naxsi-active-config.txt` (265 lines, sha256
  `de364cadd850...`). Confirmed via targeted grep on Ubuntu that all
  substantive directives are identical and at the same line numbers as the
  R11 original: `SecRulesEnabled;` (line 47), and thresholds
  `$SQL>=8 $RFI>=8 $TRAVERSAL>=4 $EVADE>=4 $XSS>=8` (lines 50-54). No
  `LearningMode`/`SecRulesDisabled`/whitelist directive present. The one
  extra line and differing hash are consistent with a formatting artifact
  of re-running `nginx -T` (e.g. a header/blank line), not a rule or
  threshold change. This closes the item — was previously "noted, not
  fully explained."
