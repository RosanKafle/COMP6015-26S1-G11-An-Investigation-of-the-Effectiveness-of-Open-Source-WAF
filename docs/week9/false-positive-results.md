# False Positive Testing Results

## Scope

- Application: DVWA
- Conditions:
  1. No WAF
  2. ModSecurity
  3. Coraza

## Method note

These results were recorded from manual DVWA navigation and simple benign inputs. Per-request raw captures were not exported into the current `docs/` evidence set.

## Test Cases

| Test ID | Normal Action | No WAF | ModSecurity | Coraza | Notes |
|---|---|---|---|---|---|
| FP-01 | Login to DVWA | Allowed | Allowed | Allowed | No blocking observed |
| FP-02 | Open DVWA homepage | Allowed | Allowed | Allowed | Normal page load |
| FP-03 | Open SQL Injection page | Allowed | Allowed | Allowed | No interference |
| FP-04 | Submit normal input `1` | Allowed | Allowed | Allowed | Normal query processed |
| FP-05 | Submit normal input `test` | Allowed | Allowed | Allowed | No blocking observed |
| FP-06 | Open XSS Reflected page | Allowed | Allowed | Allowed | Page loads correctly |
| FP-07 | Submit normal input `hello` | Allowed | Allowed | Allowed | Reflected correctly |
| FP-08 | Open Security page | Allowed | Allowed | Allowed | Configuration page accessible |

## Summary

False positive testing was conducted using normal DVWA user interactions across all three conditions: no WAF, ModSecurity, and Coraza.

All tested actions were successfully completed without being blocked, indicating that neither WAF configuration interfered with basic application functionality during standard usage.

## Observation

- No false positives were observed during normal interaction testing.
- Both ModSecurity and Coraza allowed standard user behaviour.
- WAF filtering did not impact usability for simple inputs and navigation.

## Conclusion

The results indicate that both ModSecurity and Coraza maintained good usability under default configurations, as no legitimate requests were blocked during testing.

However, it should be noted that this evaluation was limited to basic interactions. More complex or edge-case inputs in real-world scenarios may still trigger false positives depending on rule strictness and configuration.
