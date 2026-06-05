# WAF and Bypass Research Notes

## WAF Purpose

A web application firewall inspects HTTP requests and responses to detect or block malicious patterns before they reach the web application. In this project, the main WAF focus is ModSecurity with OWASP Core Rule Set.

## Detection Approaches

Signature-based detection:

- Matches known attack patterns such as SQL injection keywords, suspicious operators, script tags, traversal strings, and common scanner behavior.
- Works well against common payloads.
- Can miss modified payloads if the signature is too narrow.

Anomaly/risk-scoring detection:

- Assigns scores to suspicious request features.
- Blocks when a configured threshold is reached.
- Can detect combinations of weak signals, but may need tuning to reduce false positives.

## Common WAF Bypass Concepts

- Encoding payloads using URL encoding, double encoding, Unicode, or mixed case.
- Splitting SQL keywords or inserting comments.
- Using alternative operators or syntax.
- Sending payloads through unexpected parameters, headers, or cookies.
- Targeting logic flaws that a WAF cannot understand, such as broken access control.

## Project Relevance

These concepts explain why the project compares DetectionOnly mode, blocking mode, and CRS tuning. The same attack can be observed when only logged, then retested after blocking is enabled.

