# WAF Evaluation Report Summary

This summary is based on the authoritative CSV files in `analysis/final/`.

## Table 1: Attack Counts By Type

| Attack Type | Baseline Sent | ModSecurity Sent | Coraza Sent | NAXSI Sent |
| --- | ---: | ---: | ---: | ---: |
| authorization_bypass | 96 | 96 | 96 | 0 |
| brute_force | 245 | 245 | 241 | 0 |
| csrf | 98 | 98 | 96 | 0 |
| javascript | 147 | 146 | 144 | 0 |
| sqli | 200 | 200 | 199 | 0 |
| weak_session_ids | 147 | 144 | 144 | 0 |
| xss | 200 | 197 | 196 | 0 |

## Table 2: Detection Rate By Attack Type

| Attack Type | ModSecurity | Coraza | NAXSI |
| --- | ---: | ---: | ---: |
| authorization_bypass | 0.00% | 0.00% | No data |
| brute_force | 40.00% | 39.83% | No data |
| csrf | 0.00% | 0.00% | No data |
| javascript | 32.88% | 33.33% | No data |
| sqli | 50.00% | 49.75% | No data |
| weak_session_ids | 0.00% | 0.00% | No data |
| xss | 74.62% | 75.00% | No data |

## Table 3: False Positive Rate Under Benign Traffic

| Dataset | Baseline | ModSecurity | Coraza | NAXSI |
| --- | ---: | ---: | ---: | ---: |
| mixed / medium | 0.00% | 0.00% | 0.00% | No data |
| setup / setup | 0.00% | 0.00% | 0.00% | No data |

## Table 4: Mixed Traffic Detection Impact

| WAF | Attack-Only Detection | Mixed Detection | Detection Drop |
| --- | ---: | ---: | ---: |
| ModSecurity | 34.84% | 34.95% | -0.11% |
| Coraza | 34.77% | 35.07% | -0.30% |
| NAXSI | No data | No data | No data |

Negative detection drop means the mixed-traffic detection rate was slightly higher than the attack-only detection rate in the available run.

## Table 5: Performance Impact

| WAF | Attack-Only Avg Latency | Attack-Only Over Baseline | Mixed Avg Latency | Mixed Over Baseline |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 6.196 ms | 0.000 ms | 6.220 ms | 0.000 ms |
| ModSecurity | 7.946 ms | 1.750 ms | 9.925 ms | 3.705 ms |
| Coraza | 9.022 ms | 2.826 ms | 16.686 ms | 10.466 ms |
| NAXSI | No data | No data | No data | No data |

## Key Reading Notes

- Completed automated datasets are available for Baseline, ModSecurity, and Coraza.
- NAXSI structured outputs are not present in this repository.
- Neither ModSecurity nor Coraza blocked benign traffic in the available mixed/setup datasets.
- Logic-style weaknesses such as CSRF, weak session IDs, and authorization bypass were not meaningfully detected by either WAF in the automated data.
