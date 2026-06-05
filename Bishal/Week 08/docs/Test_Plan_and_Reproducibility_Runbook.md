# Test Plan and Reproducibility Runbook

This runbook records setup and repeatability steps for the WAF effectiveness project.

## Lab Network

Use one consistent network range in all reports and screenshots.

Recommended, based on existing screenshots:

- Attacker: Kali Linux, `192.168.56.10`.
- Target: Ubuntu Server with Apache, DVWA, ModSecurity, and OWASP CRS, `192.168.56.20`.

If the `10.10.10.0/24` network was also used, document when and why it was used. Otherwise, update future documents to use `192.168.56.0/24`.

## Evidence Folder Structure

Create folders like this when repeating tests:

```text
Evidence/
  configs/
  logs/
  screenshots/
  tool-output/
  performance/
```

Save every command output with a filename that includes the test ID, WAF mode, and date.

## Configuration Evidence to Export

Run these on the Ubuntu target and save the outputs:

```bash
apache2 -v
apache2ctl -M
modsecurity-configure --version
grep -R "SecRuleEngine" /etc/modsecurity /etc/apache2 -n
grep -R "Include.*coreruleset\|Include.*crs" /etc/apache2 /etc/modsecurity -n
sudo cp /etc/modsecurity/modsecurity.conf Evidence/configs/modsecurity.conf
sudo cp /etc/modsecurity/crs/crs-setup.conf Evidence/configs/crs-setup.conf
sudo cp /etc/apache2/sites-enabled/*.conf Evidence/configs/
```

If `modsecurity-configure` is not available, capture package versions instead:

```bash
dpkg -l | grep -Ei "apache2|modsecurity|coreruleset|crs"
```

## WAF Modes

DetectionOnly:

```apache
SecRuleEngine DetectionOnly
```

Blocking:

```apache
SecRuleEngine On
```

Restart after changes:

```bash
sudo systemctl restart apache2
sudo systemctl status apache2 --no-pager
```

## Core Test Matrix

| Test ID | Attack | Tool | Payload/target | Evidence to capture |
|---|---|---|---|---|
| T1 | SQL injection | Browser | `' OR '1'='1` | Browser result, HTTP code, WAF log |
| T2 | SQL injection | SQLMap | vulnerable `id` parameter | SQLMap terminal output, WAF log |
| T3 | XSS | Browser/ZAP | `<script>alert(1)</script>` | Browser result, ZAP alert, WAF log |
| T4 | Command injection | Browser | `; ls` | Browser result, WAF log |
| T5 | Directory traversal | Browser | `../../../../etc/passwd` | Browser result, WAF log |
| T6 | Automated scan | Nikto | target URL | Nikto output, WAF log |
| T7 | Automated scan | Wapiti | target URL | Wapiti report, WAF log |

Repeat each test in DetectionOnly and blocking mode.

## Example Commands

SQLMap:

```bash
sqlmap -u "http://192.168.56.20/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="security=low; PHPSESSID=<session>" --batch --dbs
```

Nikto:

```bash
nikto -h http://192.168.56.20/ -output Evidence/tool-output/T6_nikto_blocking.txt
```

Wapiti:

```bash
wapiti -u http://192.168.56.20/ -f html -o Evidence/tool-output/T7_wapiti_blocking
```

OWASP ZAP:

```bash
zap-baseline.py -t http://192.168.56.20/ -r Evidence/tool-output/T3_zap_baseline.html
```

WAF log capture:

```bash
sudo tail -n 200 /var/log/apache2/error.log > Evidence/logs/T1_sql_injection_blocking_error_log.txt
```

## CRS Tuning Evidence

Before tuning:

```bash
grep -n "paranoia_level" /etc/modsecurity/crs/crs-setup.conf
```

After setting paranoia level 2:

```apache
setvar:tx.paranoia_level=2
```

Capture:

- Screenshot of the edited setting.
- Raw copy of `crs-setup.conf`.
- WAF log entries for the same tests before and after tuning.
- Any false positives or usability issues.

## Performance Test Plan

Run each test three times per WAF state and save raw output.

WAF states:

1. WAF disabled or rule engine off.
2. DetectionOnly.
3. Blocking On with default CRS.
4. Blocking On with CRS paranoia level 2.

ApacheBench:

```bash
ab -n 100 -c 10 http://192.168.56.20/ > Evidence/performance/ab_blocking_pl2_run1.txt
```

hey:

```bash
hey -n 100 -c 10 http://192.168.56.20/ > Evidence/performance/hey_blocking_pl2_run1.txt
```

Record:

- Requests per second.
- Mean response time.
- 95th percentile response time.
- Failed requests.
- HTTP status distribution.

## Second WAF Evidence Requirements

Coraza/second-WAF evidence checklist:

- Installation command or package/source version.
- Reverse proxy or web server configuration.
- CRS/rule configuration.
- Screenshot proving DVWA is behind Coraza.
- SQL injection result in DetectionOnly/equivalent mode.
- SQL injection result in blocking mode.
- Log entries showing Coraza decisions.
- Performance output using the same `ab` and `hey` settings.
