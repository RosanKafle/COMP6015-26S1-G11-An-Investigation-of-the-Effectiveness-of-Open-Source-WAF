# Week 9 Report Notes

Sections to support:
- Results
- Analysis
- Discussion
- Limitations

Key points:
- Baseline testing confirmed DVWA was vulnerable before WAF protection.
- WAF testing showed that malicious requests were blocked after rule-based inspection.
- Week 7 evasion testing showed all tested payload variations were blocked.
- Week 8 saved performance testing showed measurable latency and throughput impact, but the preserved runs were not fully normalized across response type and authentication state.
- No failed requests were observed during basic load tests, indicating stable operation.
- Coraza introduced higher performance overhead than ModSecurity in the tested setup.

Limitations:
- Testing was performed only in a local lab environment.
- Payload set was limited to selected SQLi and XSS variations.
- False positive testing was basic and should be expanded in future work.
- Results may vary with different WAF tuning, traffic volume, and deployment architecture.
