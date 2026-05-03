# Light Attack Traffic Under Load

This file should be treated as a summary note. Separate raw `ab` and `sqlmap` outputs for the combined-traffic run were not preserved in the current `docs/` export.

Test setup:
- WAF path: Coraza on port 8080
- Normal load: ApacheBench, 200 requests, 10 concurrency
- Attack traffic: sqlmap against DVWA SQL Injection endpoint

Load test result:
- Complete requests: 200
- Failed requests: 0
- Non-2xx responses: 200
- Requests per second: 1620.67
- Mean time per request: 6.170 ms
- Longest request: 18 ms

Attack result:
- sqlmap did not identify injectable parameters through the WAF path.
- 403 Forbidden responses occurred 147 times.
- This indicates that the WAF continued blocking attack traffic while normal load was running.

Observation:
The WAF remained stable during combined normal load and light attack traffic. No crash was observed. The 403 responses are consistent with the broader Week 6 and Week 7 pattern of interference with automated SQLi, while the load test itself completed without failed requests.

Conclusion:
Coraza remained operational under light combined traffic according to this saved note. Because the underlying raw combined-traffic outputs are not present in `docs/`, this file should be cited as observational support rather than primary quantitative evidence.
