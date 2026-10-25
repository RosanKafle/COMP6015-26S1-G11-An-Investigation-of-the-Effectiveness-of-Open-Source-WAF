# Inherited scope and deliberate improvements

Keep existing DVWA /DVWA/ at Low security, Kali Python/ZAP, Ubuntu WAFs, CSV and logs.
Categories remain normal browsing, SQLi, reflected XSS, command injection and
traversal/file inclusion. SQLi/XSS payload templates come from the actual old script.

Command payloads now print a harmless marker; the DVWA exec form uses POST.
Traversal targets /tmp/waf-lab-marker.txt instead of system-data files.
Create that fixture on Ubuntu, then review/calibrate payloads before execution.
Inherited normal routes remain, with legitimate parameter inputs added.
Login is a real setup/verification flow; no database-reset or logout request is
included in the measured mixed corpus.

The root historical folder holds existing final-report evidence only. The 600-row
mixed cohort is separate from the 1,200-request attack batch. Never treat either as
a new-semester experiment or infer new dispositions from its status-derived labels.

XML/XXE, SSRF, authentication attacks, upload and API scenarios require separate
suitable private fixtures. They are not claimed as implemented against stock DVWA.
