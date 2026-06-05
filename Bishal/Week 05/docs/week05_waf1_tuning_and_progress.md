# Week 05 WAF #1 Blocking and Tuning Progress

## Focus

Move from detection/logging behaviour into blocking behaviour and prepare tuning notes.

## WAF Mode Progression

The testing plan uses two main ModSecurity states:

- `SecRuleEngine DetectionOnly`: malicious requests are logged but allowed.
- `SecRuleEngine On`: malicious requests are actively blocked.

## Testing Focus

The main Week 05 testing focus is to compare previously successful baseline attacks with WAF blocking enabled. SQL injection is the primary confirmed test case because it provides a clear before/after result.

## Tuning Direction

WAF tuning focuses on:

- CRS paranoia level.
- Rule strictness.
- False positives against normal traffic.
- Maintaining usability while improving attack blocking.

## Week 05 Outputs

- Mid-project proposal/progress material.
- WAF blocking-mode status evidence.
- Tuning plan for later CRS work.

