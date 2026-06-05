# Performance and Test Results Summary

This summary consolidates the performance and attack-testing evidence currently present in the folder.

## SQL Injection Results

| Test | Mode | Result | Local evidence |
|---|---|---|---|
| Manual SQL injection | DetectionOnly | Allowed; vulnerability confirmed | `results.txt`, `SQL Injection WAF Detection Only.png`, `CompSCI Report.docx` |
| Manual SQL injection | Blocking On | Blocked with HTTP 403 | `results.txt`, `WAF On - 403 Forbidden.png`, `CompSCI Report.docx` |
| SQLMap | DetectionOnly/baseline | SQLMap identified injection and extracted `dvwa` and `information_schema` | `results.txt`, `CompSCI Report.docx` |
| SQLMap | Blocking On | SQLMap blocked, failed, or significantly disrupted | `results.txt`, `CompSCI Report.docx` |

## Other OWASP Top 10 Style Tests

`DVWA Tests.docx` documents XSS, command injection, directory traversal, and Nikto tests. The GitHub-imported Week 7 test matrix also records SQL injection and XSS evasion variations.

## WAF Logging

The screenshot `Adjusting the OWASP CRS/SQL injection blocked error log.png` shows ModSecurity log output in `/var/log/apache2/error.log`, including OWASP CRS messages and requests to DVWA SQL injection paths.

Log reference command: `sudo tail -n 200 /var/log/apache2/error.log > modsecurity_error_log.txt`.

## CRS Tuning

The screenshot `Adjusting the OWASP CRS/crs paranoia level changed.png` shows `tx.paranoia_level=2` in `crs-setup.conf`.

Configuration reference files: `crs-setup.conf` and `modsecurity.conf`.

## Performance Evidence Found

ApacheBench screenshot:

- Command visible: `ab -n 100 -c 10 http://192.168.56.20/`
- Complete requests: 100.
- Failed requests: 0.
- Requests per second: 2122.25.
- Mean time per request: 4.668 ms.
- Mean time per request across concurrent requests: 0.467 ms.
- Transfer rate: 22899.43 KB/s.

hey screenshot:

- Command visible: `hey -n 100 -c 10 http://192.168.56.20/`
- Total time: 6.6210 seconds.
- Slowest response: 6.6042 seconds.
- Fastest response: 0.0013 seconds.
- Average response: 0.2891 seconds.
- Requests per second: 15.1035.
- Status code distribution: 100 responses with HTTP 200.

## Performance Comparison Evidence

The GitHub-imported performance files add a paired ApacheBench comparison for:

- WAF disabled.
- WAF DetectionOnly.
- WAF blocking enabled, default CRS.
- WAF blocking enabled, CRS paranoia level 2.

Use the same test settings for each state:

```bash
ab -n 100 -c 10 http://192.168.56.20/
hey -n 100 -c 10 http://192.168.56.20/
```

Then record average response time, requests per second, failed requests, and status-code distribution in `Local_Test_Results_Dataset.csv` or a separate performance CSV.
