"""Pure mapping from expected traffic and verified WAF disposition."""
def classify(expected_class: str, waf_action: str) -> str:
    if expected_class not in ("MALICIOUS", "NORMAL"):
        raise ValueError("Unknown expected_class.")
    if waf_action not in ("BLOCKED", "ALLOWED", "UNKNOWN"):
        raise ValueError("Unknown waf_action.")
    return {("MALICIOUS", "BLOCKED"): "TP", ("MALICIOUS", "ALLOWED"): "FN",
            ("NORMAL", "BLOCKED"): "FP", ("NORMAL", "ALLOWED"): "TN"}.get(
                (expected_class, waf_action), "UNKNOWN")
