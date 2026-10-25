# Validation of the inherited-workflow revision

Validated on 9 September 2026 (Australia/Perth).

- 27 unit tests passed, including temporary proxy/session/login fixtures, native
  audit parsing, review gates, active-scan API mocks and all earlier analysis tests.
- 111 snapshot Python files passed syntax validation.
- 78 CLI help/import checks passed.
- Every earlier-week file path remains in the next snapshot.
- All five baseline CSVs validate: 600 rows, 120 per category.
- Week 6/7 contain 1,084 generated review-gated variants, not detection outcomes.
- 43 Bash guide blocks and 3 inline Python snippets passed syntax checks.
- Original source hashes and historical CSV copies match.
- Local Markdown links resolve; no new experimental results.csv exists in raw folders.
- No-input analysis refuses to create a report.

Tests used synthetic fixtures and temporary loopback HTTP servers only. ZAP scan
orchestration was exercised with mocks, not a real installed ZAP. No Kali/Ubuntu
VM, Apache/NAXSI configuration or actual WAF experiment was executed here.
Run the guide's checkpoints on the existing lab before claiming operational success.

Concurrent benchmarking, new OWASP fixtures and measured research findings remain
incomplete. PROJECT_STATUS.md is not ticked by software generation.
