# COMP6016 Controlled WAF Validation

This directory contains the new COMP6016 experimental evidence. Historical
COMP6015 results remain separate under manual_validation and output.

## Controlled method

1. Use the same test ID and request design for every WAF.
2. Run the clean baseline before interpreting a WAF result.
3. Store payloads in raw form and apply the declared encoding exactly once.
4. Record the final wire payload actually transmitted.
5. Repeat each test three times per environment.
6. Correlate every WAF result using the X-WAF-Test-ID header.
7. Preserve requests, responses, hashes, WAF logs, rule IDs and scores.
8. Do not classify redirects or server errors as confirmed WAF blocks.
9. Calibration requests are excluded from the formal dataset.
10. Tests without a valid vulnerable backend are classified as indeterminate.

## Result classifications

- BASELINE_CONFIRMED
- BLOCKED_AND_LOGGED
- DETECTED_BUT_ALLOWED
- BLOCKED_WITHOUT_CLEAR_LOG
- ALLOWED_BYPASS
- TEST_ERROR_OR_INDETERMINATE
- FALSE_POSITIVE
