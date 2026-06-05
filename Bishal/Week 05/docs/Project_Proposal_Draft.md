# Project Proposal Draft

## Project Title

An investigation of the effectiveness of open source web application firewalls

## Background

Web applications remain a common target for attacks such as SQL injection, cross-site scripting, command injection, directory traversal, and automated vulnerability scanning. Web application firewalls (WAFs) are commonly deployed as an additional defensive layer to inspect HTTP traffic and detect or block malicious requests before they reach the application.

This project investigates how effectively open source WAF technologies can protect an intentionally vulnerable web application in a controlled lab environment. The work focuses on ModSecurity with the OWASP Core Rule Set (CRS), using DVWA as the target application and Kali Linux as the attacker machine. Where supported by evidence, a second WAF such as Coraza can be compared against ModSecurity.

## Aim

To evaluate the effectiveness, limitations, and performance impact of open source web application firewalls when defending a vulnerable web application against common web attacks.

## Objectives

1. Build a controlled lab environment containing an attacker machine, a vulnerable web application, and an open source WAF.
2. Test the application with the WAF in monitoring mode and blocking mode.
3. Evaluate WAF effectiveness against selected OWASP Top 10 web application risks.
4. Measure the performance impact introduced by WAF inspection and CRS rule processing.
5. Tune WAF rules and observe changes in blocking behavior, logging, and performance.
6. Document repeatable procedures, results, limitations, and recommendations.

## Research Questions

1. How effectively does ModSecurity with OWASP CRS detect and block common web application attacks?
2. Which attack types are strongly mitigated by a WAF, and which remain application-level weaknesses?
3. What performance overhead is introduced when WAF inspection is enabled?
4. How does CRS tuning, such as changing the paranoia level, affect detection and usability?
5. If a second WAF is tested, how does its behavior compare with ModSecurity under the same attack conditions?

## Proposed Methodology

The project uses an experimental lab-based methodology.

1. Environment setup

Set up Kali Linux as the attacker machine and Ubuntu Server as the target machine. Install Apache, DVWA, ModSecurity, and OWASP CRS on the target. Use a private host-only network, preferably matching the screenshot evidence: Kali `192.168.56.10` and Ubuntu/DVWA/WAF `192.168.56.20`.

2. Baseline testing

Run attacks against DVWA with the WAF disabled or in DetectionOnly mode. Record whether attacks execute successfully and whether the WAF logs them.

3. Blocking-mode testing

Enable `SecRuleEngine On` and repeat the same attacks. Record HTTP status codes, application behavior, tool output, and WAF log entries.

4. CRS tuning

Modify CRS settings such as `tx.paranoia_level`, repeat selected attacks, and compare detection, false positives, and performance.

5. Performance testing

Use ApacheBench and hey to compare response times and throughput across multiple WAF states:

- WAF disabled.
- DetectionOnly.
- Blocking mode with default CRS settings.
- Blocking mode after CRS tuning.

6. Analysis

Compare attack success rate, block rate, logging quality, false positives, and response-time overhead.

## Tools

- DVWA for vulnerable application testing.
- Apache web server.
- ModSecurity.
- OWASP Core Rule Set.
- Kali Linux.
- SQLMap.
- OWASP ZAP.
- Nikto.
- Wapiti.
- Burp Suite, if used.
- ApacheBench (`ab`).
- hey.

## Expected Outputs

- A documented test environment.
- A test matrix mapping attacks to WAF behavior.
- Screenshots and raw logs for each test.
- Performance comparison tables.
- WAF tuning notes.
- Final evaluation of effectiveness and limitations.

## Scope and Limitations

The project is limited to a controlled lab environment and intentionally vulnerable applications. Results may not fully represent production environments. WAF effectiveness depends on configuration quality, rule tuning, application behavior, and deployment architecture. WAFs should be treated as an additional defensive layer, not a replacement for secure development, patching, authentication controls, input validation, and monitoring.

## Ethical and Safety Considerations

Testing must be conducted only inside the controlled lab environment or against systems where explicit permission has been granted. Offensive tools such as SQLMap, Nikto, OWASP ZAP, Wapiti, and Burp Suite must not be used against third-party systems without authorization.

## Proposed Timeline

| Stage | Work |
|---|---|
| Early research | Review OWASP Top 10, WAF concepts, bypass techniques, and tool documentation. |
| Environment setup | Install and configure DVWA, Apache, ModSecurity, and OWASP CRS. |
| Baseline testing | Run attacks in DetectionOnly or WAF-disabled mode. |
| Blocking tests | Repeat attacks with WAF blocking enabled. |
| Rule tuning | Adjust CRS parameters and monitor detection behavior. |
| Performance testing | Run ab and hey under different WAF states. |
| Analysis and reporting | Consolidate results, limitations, and recommendations. |

