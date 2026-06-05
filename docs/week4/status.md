# Week 4: ModSecurity WAF Detection Mode

Focus:
Place ModSecurity in front of DVWA and confirm that malicious input is inspected by the WAF path.

Saved evidence:
- `../clean-evidence/week4-detection-artifact.md`

Evidence-backed observations:
- The preserved artifact shows the payload `1 OR 1=1` being detected by CRS rule `942100`
- The same artifact shows anomaly rule `949110` returning `403 Forbidden`
- Because the preserved response is a block, the current docs export does not prove a pure `DetectionOnly` pass-through stage by itself

Outcome:
Week 4 proves that ModSecurity was active in the request path. A clean request, response, and log set showing "logged but allowed" was not preserved in the current evidence archive.
