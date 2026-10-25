# Data management

Within each snapshot: test_cases/ holds reviewed inputs; config/ holds public
examples; private local*.json and .env hold local settings; results/raw/ holds new
immutable collection directories; results/processed/ holds reviewed/derived data;
logs/ holds real copied WAF/backend evidence; reports/ holds analysis.

Keep the existing previous-semester project intact. historical/final_report contains
unchanged copies of selected existing CSVs with source hashes; do not relabel or feed
them into the new analysis schema. Raw new results must never be manually edited.

Login passwords, API keys and cookies are not written into new run manifests.
ZAP history and real audit logs can contain authentication material: keep these
private, encrypt backups as appropriate, and redact only separate submission copies.
Candidate evidence is not approved evidence. Keep the raw log, hash and review notes.

Use separate run IDs for WAF conditions, pilots, repeats, tuning and ZAP exploration.
Do not join cohorts simply because their filenames resemble one another.
