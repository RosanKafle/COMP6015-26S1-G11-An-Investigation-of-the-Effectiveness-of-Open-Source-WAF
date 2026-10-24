# Controlled candidate variants

Run scripts/generate_variants.py to create generated_variants.csv. Generation
does not run HTTP requests. Outputs are test inputs, not experimental results.

Every generated row retains parent_test_id and transformation. Review each candidate
against the baseline, actual wire encoding and application semantics; change
review_status from REQUIRES_REVIEW to APPROVED only after that review.
Keep unapproved rows unchanged: the runner skips them and records UNKNOWN.
No baseline file is overwritten. Existing output files are protected against overwrite.

A URLENC case uses preencoded form values to avoid accidental extra encoding.
Its wire representation can equal the baseline, making it an encoding control.
DOUBLEENC deliberately adds one more percent-encoding layer. Confirm what each
proxy/application actually decodes. Do not assume this preserves semantic intent.
