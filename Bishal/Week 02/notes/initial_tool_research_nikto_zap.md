# Initial Tool Research: Nikto and OWASP ZAP

## OWASP ZAP

Purpose:

- Intercept, spider, passive scan, and actively scan web applications.
- Useful for mapping application routes and identifying common web vulnerabilities.

Expected evidence to capture:

- ZAP baseline report in HTML.
- Screenshot of alerts.
- Scan target URL and scan profile.

Example command to capture later:

```bash
zap-baseline.py -t http://192.168.56.20/ -r zap_baseline_report.html
```

## Nikto

Purpose:

- Scan web servers for known risky files, server headers, misconfigurations, and common web server issues.

Expected evidence to capture:

- Raw terminal output.
- Saved report file.
- WAF log entries showing blocked or suspicious Nikto requests.

Example command to capture later:

```bash
nikto -h http://192.168.56.20/ -output nikto_output.txt
```

## Evidence Status

No local raw ZAP or Nikto output was found. These notes support the research activity, not live tool execution.

