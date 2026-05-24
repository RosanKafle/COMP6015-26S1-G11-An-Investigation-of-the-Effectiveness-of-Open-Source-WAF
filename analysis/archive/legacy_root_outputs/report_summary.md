# WAF Evaluation Report Summary

## Table 1: Attack Counts by Type
| Attack Type | Baseline Sent | ModSecurity Sent | Coraza Sent | NAXSI Sent |
| --- | --- | --- | --- | --- |
| authorization_bypass | 98 | 96 | 94 | 0 |
| brute_force | 245 | 245 | 240 | 0 |
| csrf | 98 | 98 | 96 | 0 |
| javascript | 147 | 147 | 144 | 0 |
| sqli | 200 | 199 | 196 | 0 |
| weak_session_ids | 147 | 147 | 142 | 0 |
| xss | 200 | 196 | 196 | 0 |

## Table 2: Detection Rate by Attack Type
| Attack Type | ModSecurity | Coraza | NAXSI |
| --- | --- | --- | --- |
| authorization_bypass | 0.00% | 0.00% | 0.00% |
| brute_force | 16.33% | 40.00% | 0.00% |
| csrf | 0.00% | 0.00% | 0.00% |
| javascript | 13.61% | 33.33% | 0.00% |
| sqli | 20.60% | 50.00% | 0.00% |
| weak_session_ids | 0.00% | 0.00% | 0.00% |
| xss | 30.61% | 75.00% | 0.00% |

## Table 3: False Positive Rate Under Benign Traffic
| Load Level | ModSecurity | Coraza | NAXSI |
| --- | --- | --- | --- |
| none | 0.00% | 0.00% | 0.00% |
| low | 0.00% | 0.00% | 0.00% |
| medium | 0.00% | 0.00% | 0.00% |
| high | 0.00% | 0.00% | 0.00% |

## Table 4: Mixed Traffic Detection Impact
| WAF | Attack Only Detection | Mixed Detection | Detection Drop |
| --- | --- | --- | --- |
| ModSecurity | 34.77% | 0.00% | 34.77% |
| Coraza | 35.09% | 35.12% | -0.03% |
| NAXSI | 0.00% | 0.00% | 0.00% |

## Table 5: Performance Impact
| WAF | Avg Latency No Load | Avg Latency Mixed Low | Avg Latency Mixed Medium | Avg Latency Mixed High |
| --- | --- | --- | --- | --- |
| ModSecurity | 9.195 | 0.000 | 6.693 | 0.000 |
| Coraza | 13.176 | 0.000 | 19.107 | 0.000 |
| NAXSI | 0.000 | 0.000 | 0.000 | 0.000 |
