# Work sync — 21 September 2026

Kali sends tests; Ubuntu hosts DVWA and the WAFs. Do not switch their roles.

Reviewed baseline: r11-baseline-20260921T072551Z-8696e008. The two uploaded archives were identical. All 56 saved request/response hashes matched their records. Seven SQLi cases increased returned records, five command cases produced canary output, and two path cases included the canary file. Browser output supplied by the user confirmed seven XSS cases in isolated offline replay. This does not establish live-origin browser behavior.

Exclude R11-SQLI-E03, R11-XSS-E04 and R11-PTH-E03 from the effective-attack denominator: their double-encoded forms did not establish the intended baseline effect. Retain original evidence. Do not count these as WAF defenses or bypasses.

Next collection: 21 attacks and four controls, three repetitions, ModSecurity/Coraza/NAXSI: 225 planned observations (189 attack; 36 control). No protected R11 results exist at preparation time. The added runner checks source hashes and browser evidence before sending. It preserves existing evidence and writes a new run. Requests and responses exclude credential headers; HTML response bodies are retained for analysis.

All HTTP403 responses remain block candidates pending correlated server evidence. HTTP200 and marker presence require effect review; reflection alone is not XSS execution. Benign failures require legitimate baseline semantics and WAF attribution. No global superiority or statistical significance claims. Timing includes application behavior and is not a performance benchmark.

Earlier v10 evidence is separate: NAXSI newline command case produced canary output in three observations, with correlated access logs; exact reason for the miss remains unproven. Some v10 purported encoding variants were identical on the wire. Do not merge their technique counts with R11. Withdraw v10 BEN-E04 false-positive classification: its file-parameter input was not established as legitimate.

After collection: preserve Ubuntu access/audit/error logs including rotations and Coraza container logs/configuration; correlate run ID, case ID, repetition, timestamp and native transaction ID. Existing NAXSI access format may omit run/repetition; do not silently match duplicate case IDs. Explain actual detection rules separately from aggregate blocking rules. Preserve configured thresholds, enforcement mode, exclusions and rule versions. XML remains unexecuted; broader repeated tests and root-cause follow-ups remain unfinished. Calendar weeks must follow actual timestamps; directory labels do not establish completion dates.
