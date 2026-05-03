# Week 5: ModSecurity BLOCKING Mode CONFIRMED

## Recorded configuration note

- Lab notes for this week state that ModSecurity enforcement was moved to an active deny configuration.
- The exported repo does not include the live config file, so this should be treated as recorded context rather than directly reproducible config evidence.

## Evidence-backed observations

- The later saved sqlmap run in `../week6/sqlmap-waf1-week6.txt` ended with no injectable parameter detected
- The same run recorded `500 (Internal Server Error)` 908 times
- This behaviour is consistent with active disruption of automated SQLi probing on the ModSecurity path

## Progression

- Week 3 baseline: manual SQLi and XSS succeeded without WAF protection
- Week 4 saved artifact: ModSecurity inspection and blocking are visible in the preserved log/request example
- Week 5 onward: automated probing is disrupted rather than behaving like the baseline

Next:
Week 6 introduces the Coraza comparison path.
