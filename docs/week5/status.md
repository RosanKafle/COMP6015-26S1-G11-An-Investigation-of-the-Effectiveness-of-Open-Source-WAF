# Week 5: ModSecurity BLOCKING Mode CONFIRMED
## Config Fixed
- /etc/apache2/mods-enabled/security2.conf: SecRuleEngine On  
- SecDefaultAction: phase:1,deny,status:403

## sqlmap Evidence (BLOCKING works)
[*] GET parameter 'id' does not seem to be injectable
[CRITICAL] all tested parameters do not appear to be injectable
HTTP 500 errors = BLOCKED (Week 4: passed through)

## Progression
Week 4: Logged, 200 OK
Week 5: BLOCKED (500)

[Screenshot: sqlmap output above]

Next: Week 6 CRS rules tuning
