# Inherited mixed workload

Five category CSVs contain seeded 600 input rows, 120 normal plus 120 per category.
config/inherited_test_templates.json records source IDs and deliberate changes.
Repeated templates are not independent payloads and these inputs are not results.
Generate a separate corpus with scripts/build_mixed_corpus.py --output traffic/new-corpus.
The runner accepts --test-directory traffic/new-corpus.

Review semantic validity on your DVWA and create the marker fixture before execution.
Imported ZAP cases and variants remain REQUIRES_REVIEW until manually approved.
