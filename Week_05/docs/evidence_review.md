# Evidence review and immutable results

Raw results default to UNKNOWN regardless of HTTP status. Save real WAF audit and
backend access logs under logs/. Configure your lab to log X-Lab-Request-ID, and
validate that the value survives the proxy path. scripts/parse_modsecurity_audit.py parses native ModSecurity B/H transactions into
rule_events.csv and review-gated block_candidates.csv. Other formats and NAXSI
require their own evidence review. Candidate notes must be replaced with a genuine
review rationale before apply_evidence.py accepts them.

Create a real reviewed CSV with these columns:

```text
run_id,waf,test_id,request_id,waf_action,evidence_reference,notes
```

Copy correlation values from the raw CSV. Cite a retained log filename and exact
transaction/line identifier; explain why it proves WAF intervention or passage to
the intended application. A detection warning alone is insufficient. For ALLOWED,
verify application/session state; redirects and unrelated 403s are usually UNKNOWN.

Run scripts/apply_evidence.py with --raw, --evidence and --output. It writes a new
processed CSV plus source hashes. It does not verify that human assertions are true.
Never fill decisions from expectations or from guessed outcomes. Unreviewed rows
remain UNKNOWN. Preserve the source files cited by every decision.

Response binaries and request metadata may contain sensitive application data.
Cookies are omitted from manifests/request metadata; response bodies can still
contain secrets. Keep raw storage private and sanitize copies for assessment.
