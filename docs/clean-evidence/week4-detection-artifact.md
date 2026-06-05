# Week 4 Saved ModSecurity Artifact

## Attack Request

GET /DVWA/vulnerabilities/sqli/?id=1%20OR%201%3D1&Submit=Submit HTTP/1.1  
Host: 127.0.0.1  

## WAF Response

HTTP Status: 403 Forbidden  

## WAF Log Evidence
ModSecurity: Warning. detected SQLi using libinjection
[id "942100"]
[msg "SQL Injection Attack Detected via libinjection"]
[data "Matched Data: 1&1 found within ARGS:id: 1 OR 1=1"]

ModSecurity: Access denied with code 403
[id "949110"]
[msg "Inbound Anomaly Score Exceeded (Total Score: 8)"]


## Explanation

The SQL injection payload `1 OR 1=1` was detected by ModSecurity using the OWASP Core Rule Set. Rule ID 942100 identified the input as a SQL injection pattern using libinjection. The request accumulated a high anomaly score, which triggered rule ID 949110, resulting in the request being blocked with a 403 Forbidden response.

This confirms that ModSecurity actively inspected the request path and blocked malicious input based on rule-based detection and anomaly scoring.

## Scope note

Despite the original filename, the preserved artifact is a blocking example, not a pure `DetectionOnly` pass-through example. The current docs export does not contain a request and matching log excerpt that proves the payload was logged but allowed.

