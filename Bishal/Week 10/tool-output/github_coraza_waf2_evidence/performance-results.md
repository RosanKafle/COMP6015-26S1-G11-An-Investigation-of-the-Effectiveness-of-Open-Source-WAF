# Week 8 Performance Results

## Baseline Performance (No WAF) TEST number 1

Test command:
`ab -n 100 -c 10 http://127.0.0.1/DVWA/`

Results:
- Total requests: 100
- Concurrency: 10
- Failed requests: 0
- Non-2xx responses: 100
- Requests per second: 9552.01
- Mean time per request: 1.047 ms
- Longest request: 3 ms

Observation:
The baseline test completed successfully with no failed requests. The server responded very quickly, with a mean request time of 1.047 ms. However, all responses were non-2xx and the document length was 0 bytes, indicating that the test likely measured the DVWA redirect/login response rather than a fully authenticated application page.

So ab is not using the logged-in browser session. I found out that it is normal because ab does not automatically share Firefox cookies.

Using this result as my simple unauthenticated baseline, but for a better Week 8 result I will test a static DVWA page or try to include cookies.

-------------------------------------------------------------------------------------------------------------------------------------------------------
## Baseline Performance (No WAF – Authenticated) TEST number 2

Test command:
`ab -n 100 -c 10 -H "Cookie: security=low; PHPSESSID=..." http://127.0.0.1/DVWA/index.php`

Results:
- Total requests: 100
- Concurrency: 10
- Failed requests: 0
- Document length: 6436 bytes
- Requests per second: 15757.96
- Mean time per request: 0.635 ms

Observation:
The authenticated baseline test produced valid 200 responses with consistent document size (6436 bytes). The system showed very high throughput and low latency, indicating minimal overhead in the absence of a WAF.

--------------------------------------------------------------------------------------------------------------------------------------------------------
## Performance with WAF #1 (ModSecurity + OWASP CRS)

Test command:
`ab -n 100 -c 10 -H "Cookie: security=low; PHPSESSID=..." http://127.0.0.1/DVWA/index.php`

Results:
- Total requests: 100
- Concurrency: 10
- Failed requests: 0
- Document length: 6436 bytes
- Requests per second: 767.12
- Mean time per request: 13.036 ms

Observation:
With ModSecurity enabled, there is a significant decrease in performance compared to the baseline. Requests per second dropped sharply, and response time increased substantially, indicating noticeable overhead introduced by WAF processing and rule inspection.

---------------------------------------------------------------------------------------------------------------------------------------------------------
## Performance with WAF #2 (Coraza + OWASP CRS)

Test command:
`ab -n 100 -c 10 -H "Cookie: security=low; PHPSESSID=..." http://127.0.0.1:8080/DVWA/index.php`

Results:
- Total requests: 100
- Concurrency: 10
- Failed requests: 0
- Document length: 6436 bytesa
- Requests per second: 173.13
- Mean time per request: 57.760 ms
- Longest request: 128 ms

Observation:
Coraza completed the test without failed requests, confirming stable operation under the tested load. However, compared with both the no-WAF baseline and ModSecurity, Coraza introduced the highest latency and lowest throughput in this test.

-----------------------------------------------------------------------------------------------------------------------------------------------------------
## Week 8 Performance Comparison

| Metric            | No WAF     | ModSecurity| Coraza     |
|-------------------|------------|------------|------------|
| Requests/sec      | 15757.96   | 767.12     | 173.13     |
| Mean time/request | 0.635 ms   | 13.036 ms  | 57.760 ms  |
| Failed requests   | 0          | 0          | 0          |
| Document length   | 6436 bytes | 6436 bytes | 6436 bytes |

Analysis:
All three configurations completed 100 requests with no failed requests, showing that the environment remained stable during the basic load test. The no-WAF baseline had the highest throughput and lowest latency. ModSecurity introduced noticeable overhead, while Coraza introduced the highest overhead in this test. This supports the project finding that WAFs improve inspection and blocking capability, but add measurable performance cost.

--------------------------------------------------------------------------------------------------------------------------------------------------------------
