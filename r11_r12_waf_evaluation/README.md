# Corrected transport stage

Run on Kali using the existing Python environment with requests installed.

Offline only:

    /home/sadaiba/COMP6016_S2_2026/week6-runtime.d5AqGB/bin/python run_corrected.py

Baseline collection (prompts for password; creates a unique evidence directory):

    /home/sadaiba/COMP6016_S2_2026/week6-runtime.d5AqGB/bin/python run_corrected.py --baseline

Requires waf-lab.local to resolve to the current Ubuntu lab host; baseline port 8081.
No WAF settings are changed. The inherited login helper establishes an authenticated
session and requests DVWA low security, recording any manual security-cookie override.
An outgoing low cookie does not independently prove application security state.

No protected tests are enabled here. Review baseline effects first. HTTP 200 and
marker presence alone do not validate SQLi, browser execution, or file inclusion.
Compare SQL results with R11-BEN-SQL01. Confirm command markers in command output,
file markers in actual included content, and XSS markers through isolated browser
execution before approving those cases for efficacy calculations.

Encoding check failures, authentication failures, redirects, and exceptions return
nonzero. Old evidence is never overwritten. Re-running creates a fresh directory.
See WORK_SYNC.md for the current evidence status and pending work.
