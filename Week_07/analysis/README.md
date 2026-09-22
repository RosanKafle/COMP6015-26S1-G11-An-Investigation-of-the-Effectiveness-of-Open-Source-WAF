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

## Week 7 analysis

Supply one real collected or evidence-enriched CSV per WAF/run. Core metric/report CLIs take --input and --output. rule_analysis.py additionally
requires --events and --output-directory; latency_summary.py requires --output. Without real input, no report is written.
metrics.py emits JSON; zero denominators are null. CSV zero-denominator rates are
empty; Markdown rates are N/A. Counts of observed rows may legitimately be zero,
but absent measurements never become zero-valued rates.

category_summary.py defines total_malicious as received HTTP responses; errors and
skips are separate. Its detection denominator is blocked + allowed, excluding unknown.
missed_detection_analysis.py exports only FN rows with original payload/parent metadata.
confusion_matrix.py includes UNKNOWN separately. generate_analysis_report.py produces
all nine report sections and within-run baseline/variant pairing; it never fills in
a missing WAF run or variant condition. Graph generation remains future work.

rule_analysis.py reports observed native CRS rule groups and multiple category matches,
not expected-label guesses. latency_summary.py summarises actual client timings;
concurrent throughput and isolated WAF overhead are not inferred.
