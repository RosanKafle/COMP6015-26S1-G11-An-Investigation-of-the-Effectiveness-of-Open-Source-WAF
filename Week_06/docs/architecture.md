# Inherited laboratory architecture

Reference: final report Sections 3â€“6 and the original Python pipelines.
Addresses are examples reported previously, not verified current hosts.

~~~text
Kali DFIR01 (example 192.168.56.10)
  Inherited Python entry points + authenticated DVWA session
    -> OWASP ZAP API/proxy (Kali 127.0.0.1:8080)
    -> VirtualBox host-only network
Ubuntu (example 192.168.56.20)
  Condition A: existing Apache + ModSecurity/CRS -> DVWA /DVWA/
  Condition B: existing Nginx + NAXSI -> existing Apache/DVWA backend
    -> HTTP responses + ZAP exports + WAF/backend logs
    -> Kali: request correlation, comparison and analysis
~~~

~~~mermaid
flowchart TD
 P["Kali: inherited Python pipelines"] --> Z["Kali: ZAP API and proxy"]
 Z --> M["Ubuntu: ModSecurity and CRS"]
 Z --> N["Ubuntu: Nginx and NAXSI"]
 M --> D["Existing DVWA and database"]
 N --> B["Apache backend with ModSecurity off for NAXSI"]
 B --> D
 M --> L["WAF logs"]
 N --> L
 D --> R["HTTP and backend evidence"]
 L --> A["Kali analysis"]
 R --> A
~~~

Reuse verified services and rule versions. Conditions can use the same IP/port
sequentially with documented VM snapshots, or existing distinct listeners.
The runner does not install a replacement stack or silently switch WAFs.
NAXSI must not pass through an enforcing ModSecurity backend.

Kali's ZAP loopback and Ubuntu's backend loopback belong to different VMs.
The same numeric port on those separate VMs is not a conflict.
Use NAT for downloads only. For active scans disconnect NAT on both VMs, retain
host-only connectivity and verify that the host does not forward this subnet.
ZAP scope is an additional control, not a substitute for network isolation.
