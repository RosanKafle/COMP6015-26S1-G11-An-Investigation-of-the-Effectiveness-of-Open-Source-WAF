# Week 8 Performance Results

This summary is limited to the ApacheBench outputs that are actually saved in `docs/week8/`. Earlier draft figures that are not backed by a saved raw file have been removed.

## Saved raw test 1: baseline path

Source:
`baseline-load.txt`

Target:
`http://127.0.0.1/DVWA/`

Saved metrics:
- Complete requests: 100
- Concurrency: 10
- Failed requests: 0
- Non-2xx responses: 100
- Document length: 0 bytes
- Requests per second: 13800.72
- Mean time per request: 0.725 ms
- Longest request: 1 ms

Interpretation:
This is an unauthenticated or redirect-style response, not a full logged-in page benchmark.

## Saved raw test 2: ModSecurity path

Source:
`modsecurity-load.txt`

Target:
`http://127.0.0.1/DVWA/index.php`

Saved metrics:
- Complete requests: 100
- Concurrency: 10
- Failed requests: 0
- Non-2xx responses: 100
- Document length: 0 bytes
- Requests per second: 2157.59
- Mean time per request: 4.635 ms
- Longest request: 8 ms

Interpretation:
The saved ModSecurity run also returned non-2xx zero-byte responses, so it should be compared cautiously with the saved baseline.

## Saved raw test 3: Coraza path

Source:
`coraza-load.txt`

Target:
`http://127.0.0.1:8080/DVWA/index.php`

Saved metrics:
- Complete requests: 100
- Concurrency: 10
- Failed requests: 0
- Document length: 6436 bytes
- Requests per second: 159.20
- Mean time per request: 62.812 ms
- Longest request: 120 ms

Interpretation:
This saved run returned a full page body and showed the heaviest overhead in the stored dataset.

## Saved comparison table

| Metric | Baseline saved run | ModSecurity saved run | Coraza saved run |
|--------|--------------------|-----------------------|------------------|
| Requests/sec | 13800.72 | 2157.59 | 159.20 |
| Mean time/request | 0.725 ms | 4.635 ms | 62.812 ms |
| Failed requests | 0 | 0 | 0 |
| Non-2xx responses | 100 | 100 | 0 reported |
| Document length | 0 bytes | 0 bytes | 6436 bytes |

## Limitations

- The saved runs are not fully normalized across authentication state and response body size
- `baseline-load.txt` and `modsecurity-load.txt` show zero-byte non-2xx responses, while `coraza-load.txt` shows a full `6436` byte page body
- These files support preliminary overhead observations, not a strict authenticated head-to-head benchmark

## Evidence-backed takeaway

- All three saved runs completed without failed requests
- The saved Coraza run had the lowest throughput and highest latency in this dataset
- Additional normalized tests would be needed for a stronger final performance comparison
