# Inherited environment inventory

| Component | Hostname | IP address | Operating system | Purpose | Status |
|---|---|---|---|---|---|
| Generator | DFIR01 reported | 192.168.56.10 example | Kali, verify version | Python and ZAP | NOT VERIFIED |
| ZAP | Kali loopback | 127.0.0.1:8080 example | ZAP 2.17.0 reported | Proxy and API | NOT VERIFIED |
| ModSecurity/CRS | Existing Ubuntu VM | 192.168.56.20 example | Ubuntu/Apache, verify | WAF condition A | NOT VERIFIED |
| NAXSI | Existing Ubuntu VM | Verify listener | Existing Nginx, verify | WAF condition B | NOT VERIFIED |
| DVWA | Existing Ubuntu VM | Verify /DVWA/ backend | Existing PHP/database | Same target | NOT VERIFIED |

Record actual ports, versions, rule paths, enforcement modes, VM resources and routes.
The old report does not prove that any service is running now.
