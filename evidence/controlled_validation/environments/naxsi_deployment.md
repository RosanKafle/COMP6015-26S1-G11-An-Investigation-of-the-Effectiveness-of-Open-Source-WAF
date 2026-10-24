# NAXSI controlled deployment

## Environment

- WAF: NAXSI
- Release: 1.7
- Release commit: 867a61f16be7f55fed65bb538de87eb64df71a77
- Architecture: ARM64
- NGINX: Ubuntu 1.28.3-2ubuntu1.10
- Public test path: http://waf-lab.local:8084/DVWA
- Backend: http://127.0.0.1:8081/DVWA
- Service: comp6016-naxsi.service

## Compatibility change

A one-line compiler compatibility patch removes an unnecessary const cast
from a strchr call. It allows NAXSI 1.7 to compile with Ubuntu 26.04's
compiler and mandatory -Werror setting. No rules, thresholds or detection
logic were changed.

## Blocking thresholds

- SQL: 8
- RFI: 8
- Traversal: 4
- Evasion: 4
- XSS: 8

## Integrity

- Module SHA-256: 8d41fafa15146f984b87108c84ef864023d54afda4eef074b0bb233db3735b22
- Core-rules SHA-256: dc2afe04a9861ac8011bbabb23635b5e80617aa1c444d461a0ba6868bd00d433
- Patch SHA-256: d3175071aeebcee3cfd3819b34a5fec99ed0bd3e3edef97cdaaf1a036f8185cf

## Calibration result

The same GET request containing `<script>alert(1)</script>` was sent to
the baseline, ModSecurity, Coraza and NAXSI paths.

- Baseline: HTTP 200
- ModSecurity: HTTP 403
- Coraza: HTTP 403
- NAXSI: HTTP 403

NAXSI matched rule 1010 in the ARGS zone, recorded an XSS score of 8 and
blocked the request. Benign login requests returned HTTP 200 through all
four paths.
