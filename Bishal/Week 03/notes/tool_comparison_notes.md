# Security Testing Tool Comparison Notes

| Tool | Role in project | Best evidence to save |
|---|---|---|
| OWASP ZAP | Proxy, spidering, passive/active scanning | HTML report, alerts screenshot, target URL |
| Burp Suite | Intercepting proxy and manual request testing | Request/response screenshots, project notes |
| SQLMap | Automated SQL injection testing | Raw terminal output, command used, WAF log excerpt |
| Nikto | Web server vulnerability and misconfiguration scanning | Text report, terminal output |
| Wapiti | Web application scanner | HTML report or terminal output |

## Tool Selection Notes

SQLMap is the strongest fit for proving SQL injection effectiveness because it can show whether data extraction works before WAF blocking and fails after blocking.

OWASP ZAP, Nikto, and Wapiti are useful for broader scanning evidence, but their outputs must be saved locally. Without raw reports or screenshots, they remain research claims rather than execution evidence.

