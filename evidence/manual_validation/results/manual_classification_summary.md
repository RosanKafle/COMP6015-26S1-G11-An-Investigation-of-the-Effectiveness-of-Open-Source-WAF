# Manual Evidence Classification Summary

This file explains what was blocked, what was not cleanly blocked, and how each outcome was classified.

Clean WAF block is defined as HTTP 403, 406, or 501. Redirects and HTTP 500 server errors are not counted as clean WAF detections.


## Classification summary

| attack_family   | environment   | outcome_class                | classification_correctness            |   count |   avg_response_time_ms |
|:----------------|:--------------|:-----------------------------|:--------------------------------------|--------:|-----------------------:|
| csrf            | baseline      | baseline_allowed_expected    | expected_baseline_vulnerable          |       5 |                 1.938  |
| csrf            | coraza        | clean_waf_block              | blocked_but_likely_generic_input_rule |       1 |                 2.7    |
| csrf            | coraza        | redirected_not_clean_block   | not_clean_detection_redirect          |       4 |                 4.79   |
| csrf            | modsec        | clean_waf_block              | blocked_but_likely_generic_input_rule |       1 |                 2.7    |
| csrf            | modsec        | redirected_not_clean_block   | not_clean_detection_redirect          |       4 |                 2.9975 |
| sqli            | baseline      | baseline_allowed_expected    | expected_baseline_vulnerable          |      10 |                 1.916  |
| sqli            | baseline      | server_error_not_clean_block | baseline_application_error            |       2 |                 1.755  |
| sqli            | coraza        | clean_waf_block              | correct_attack_block                  |      10 |                 2.348  |
| sqli            | coraza        | server_error_not_clean_block | not_clean_detection_server_error      |       2 |                 5.58   |
| sqli            | modsec        | clean_waf_block              | correct_attack_block                  |      10 |                 1.956  |
| sqli            | modsec        | server_error_not_clean_block | not_clean_detection_server_error      |       2 |                 3.285  |


## Manual confusion-style summary

| attack_family   | environment   |   attack_requests |   true_positive_clean_blocks |   false_negative_allowed |   redirected_not_clean_block |   server_error_not_clean_block |   clean_block_recall_percent | note                                                                                                     |
|:----------------|:--------------|------------------:|-----------------------------:|-------------------------:|-----------------------------:|-------------------------------:|-----------------------------:|:---------------------------------------------------------------------------------------------------------|
| csrf            | coraza        |                 5 |                            1 |                        0 |                            4 |                              0 |                        20    | Manual attack-only evidence; benign true negatives/false positives require mixed or benign traffic data. |
| csrf            | modsec        |                 5 |                            1 |                        0 |                            4 |                              0 |                        20    | Manual attack-only evidence; benign true negatives/false positives require mixed or benign traffic data. |
| sqli            | coraza        |                12 |                           10 |                        0 |                            0 |                              2 |                        83.33 | Manual attack-only evidence; benign true negatives/false positives require mixed or benign traffic data. |
| sqli            | modsec        |                12 |                           10 |                        0 |                            0 |                              2 |                        83.33 | Manual attack-only evidence; benign true negatives/false positives require mixed or benign traffic data. |


## Key interpretation

- SQLi clean blocks indicate the WAF recognised payload/signature-style attack patterns.

- SQLi server errors are not counted as clean detections because they indicate application/proxy error behaviour.

- CSRF redirects are not clean WAF detections.

- CSRF clean block on the special-character password likely reflects generic input filtering, not semantic CSRF detection.

- Manual evidence does not include benign traffic, so full false-positive analysis should use mixed/benign automated datasets.
