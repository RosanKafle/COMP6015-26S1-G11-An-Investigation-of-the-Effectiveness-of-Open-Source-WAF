# Docs Evidence Guide

This `docs/` folder is an exported evidence archive for a DVWA-only WAF evaluation. It is not the live lab environment or a complete configuration repository.

## Environment

See `environment.md` for the lab context and provenance note.

## Authoritative evidence chain

- Scope: `clean-evidence/scope.md`
- Baseline summary: `clean-evidence/baseline/baseline-summary.md`
- Baseline supporting evidence:
  - `clean-evidence/baseline/manual-sqli-baseline.txt`
  - `clean-evidence/baseline/manual-xss-baseline.txt`
  - `clean-evidence/baseline/sqlmap-authenticated-baseline.txt`
  - `clean-evidence/baseline/sqlmap-authenticated-baseline-test-output.txt`
- First saved ModSecurity artifact: `clean-evidence/week4-detection-artifact.md`
- Week 5 enforcement summary: `week5/status.md`
- Week 6 comparison set:
  - `week6/status.md`
  - `week6/waf1-sqlmap-notes.md`
  - `week6/sqlmap-waf1-week6.txt`
  - `week6/sqlmap-waf2.txt`
  - `week6/wapiti-waf2.txt`
  - `week6/baseline-waf2-results.md`
- Week 7 evasion set:
  - `week7/status.md`
  - `week7/week7-test-matrix.md`
  - `week7/burp/W7-01-sqli-url-encoding`
  - `week7/notes`
  - `week7/sqlmap/W7-03-sqlmap-tamper-space2comment.txt`
- Week 8 load and stability set:
  - `week8/baseline-load.txt`
  - `week8/modsecurity-load.txt`
  - `week8/coraza-load.txt`
  - `week8/performance-results.md`
  - `week8/light-attack-under-load.md`
- Week 9 synthesis:
  - `week9/false-positive-results.md`
  - `week9/final-results.md`
  - `week9/status.md`
  - `week9/report-notes.md`

## Draft, retained, or excluded material

- `week3/` retains original baseline tool outputs. For final reporting, use `clean-evidence/baseline/` and `week3/status.md` as the authoritative Week 3 interpretation.
- `week4/status.md` explains the limitation in the saved Week 4 artifact. The exported evidence does not preserve a clean DetectionOnly pass-through example.
- `week3/week3_rule_rationale.md`, `week3/week3_precision_recall.txt`, and `week3/week3_before_after_comparison.txt` are unrelated Suricata threshold-tuning notes and are excluded from the final DVWA WAF analysis.
- `week7/burp/w7_` is an unlabeled duplicate export and should not be cited as primary evidence.
- `week10/` contains only a status note because no additional experimental artifact was exported into that folder.
