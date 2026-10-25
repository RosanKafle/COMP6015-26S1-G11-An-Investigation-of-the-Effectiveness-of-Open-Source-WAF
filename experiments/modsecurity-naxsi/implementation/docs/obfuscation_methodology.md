# Controlled obfuscation methodology

Baseline request -> controlled transformation -> verify same semantic attack intent ->
execute against the same WAF -> compare detection behaviour.

The verification step is essential. The framework creates candidates, not a claim of
equivalence. SQL keyword case changes preserve quoted literals in the starter corpus;
whitespace, separator and harmless-comment candidates are limited to SQLi. XSS case
variation changes tag names while preserving JavaScript strings. URL and double
encoding apply to the inherited SQLi/XSS corpus. HTML entity encoding is an XSS candidate that
may cease to be an attack in a particular parser context and should then remain
unapproved/excluded. Arbitrary SQL syntax and nested quoting need manual review.

Fields added: parent_test_id, transformation, wire_encoding, review_status.
The loader has reserved compatible defaults from Week 3; Week 6 first populates them.
Variant IDs concatenate baseline IDs and transformation names. Baseline files and
reviewed variant sets must be frozen before comparing WAFs. Run the baseline and
approved variants together so Week 7 can pair them within the same experiment.

Inspect recorded encoded_fields in request metadata and the WAF/backend observation
of that value. The runner sends preencoded values verbatim as one form value, and
validates their character set so a variant cannot inject unrelated parameters.
Never label a skipped, invalid or unreviewed candidate as a false negative.

The old semester's payload-category hypotheses are starting points for investigation,
not proof of normalization defects. Browser execution, backend semantics, rule traces
and repeated paired tests are needed to distinguish missed inspection from inert text.
