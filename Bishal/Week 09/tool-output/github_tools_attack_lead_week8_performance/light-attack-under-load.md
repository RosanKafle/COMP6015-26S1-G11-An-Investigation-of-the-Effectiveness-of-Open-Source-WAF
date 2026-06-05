# Light Attack Traffic Under Load

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
The WAF remained stable during combined normal load and light attack traffic. No crash was observed. The 403 responses suggest that malicious requests were blocked, while the load test itself completed without failed requests.

Conclusion:
Coraza remained operational under light combined traffic. The results support the finding that WAF protection continued during load, although non-2xx responses and inspection overhead should be considered in the final performance analysis.
