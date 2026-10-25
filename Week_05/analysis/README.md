# Comparison infrastructure

comparison_template.csv is a non-data template. Its single placeholder row must never
be included in any experiment. The comparison program rejects it as an input.

Use the same --category, test files and variant selection for both runs. The plan and
run manifest expose a test-set SHA-256; pass it using --expect-test-set-sha256 for the
second WAF. merge_results.py verifies digests, exact ID sets and case content.
Supply one run per WAF; missing cases and duplicates are errors, not fabricated rows.

Collect/verify actions with scripts/apply_evidence.py first. Merging unreviewed real
raw data is possible but yields UNKNOWN outcomes and cannot establish superiority.
An independent DVWA calibration, equivalent sessions/rules and repetitions remain
researcher responsibilities. No baseline comparison has been executed here.
