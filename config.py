"""Central configuration for the WAF evaluation framework.

Important network separation:
- 127.0.0.1 is the Kali attacker machine where OWASP ZAP runs.
- 192.168.209.130 is the Ubuntu target machine where DVWA runs.

Do not point a DVWA target at 127.0.0.1:8080 unless DVWA is genuinely running
there. In the default lab topology, 127.0.0.1:8080 is ZAP's API/proxy endpoint,
not the protected application.
"""

from dataclasses import dataclass
from pathlib import Path
import os


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"


def _env(name: str, default: str) -> str:
    return os.getenv(name, default).strip()


def _target(name: str, default: str) -> str:
    return _env(name, default).rstrip("/")


# ZAP_API controls ZAP through its REST API. The application must never try to
# login to this URL.
ZAP_API = _env("ZAP_API", "http://127.0.0.1:8080").rstrip("/")

# ZAP_PROXY is used only when framework-generated HTTP traffic should be
# intercepted by ZAP. Enable this path with experiment_runner.py --use-zap-proxy.
ZAP_PROXY = _env("ZAP_PROXY", "http://127.0.0.1:8080").rstrip("/")
ZAP_API_KEY = _env("ZAP_API_KEY", "")


TARGETS = {
    "baseline": {
        "waf_type": "none",
        "base_url": _target("BASELINE_BASE_URL", "http://192.168.209.130/DVWA"),
    },
    "modsec": {
        "waf_type": "modsecurity",
        "base_url": _target("MODSEC_BASE_URL", "http://192.168.209.130/DVWA"),
    },
    "coraza": {
        "waf_type": "coraza",
        "base_url": _target("CORAZA_BASE_URL", "http://192.168.209.130:8080/DVWA"),
    },
    "naxsi": {
        "waf_type": "naxsi",
        "base_url": _target("NAXSI_BASE_URL", "http://192.168.209.130:8084/DVWA"),
    },
}


DVWA_USERNAME = _env("DVWA_USERNAME", "admin")
DVWA_PASSWORD = _env("DVWA_PASSWORD", "password")
DEFAULT_SECURITY_LEVEL = _env(
    "DEFAULT_SECURITY_LEVEL", _env("DVWA_SECURITY_LEVEL", "low")
)

DEFAULT_REQUEST_TIMEOUT_SECONDS = float(_env("REQUEST_TIMEOUT_SECONDS", "15"))
BACKGROUND_INTERVAL_SECONDS = float(_env("BACKGROUND_INTERVAL_SECONDS", "1.0"))
ATTACK_DELAY_SECONDS = float(_env("ATTACK_DELAY_SECONDS", "0.25"))
ZAP_ALERT_WAIT_SECONDS = float(_env("ZAP_ALERT_WAIT_SECONDS", "2.0"))
MIXED_PHASE_WARMUP_SECONDS = float(_env("MIXED_PHASE_WARMUP_SECONDS", "10"))

ATTACK_TYPES = [
    "sqli",
    "xss",
    "brute_force",
    "csrf",
    "javascript",
    "weak_session_ids",
    "authorization_bypass",
]

LOAD_PROFILES = {
    "none": {"threads": 0, "delay": 0},
    "low": {"threads": 5, "delay": 1.0},
    "medium": {"threads": 15, "delay": 0.5},
    "high": {"threads": 40, "delay": 0.1},
}


@dataclass(frozen=True)
class EnvironmentConfig:
    """Target and WAF metadata for one experimental condition."""

    name: str
    waf_type: str
    base_url: str
    request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS

    @property
    def target_url(self) -> str:
        """Backward-compatible alias for older modules."""

        return self.base_url


ENVIRONMENTS = {
    name: EnvironmentConfig(
        name=name,
        waf_type=target["waf_type"],
        base_url=target["base_url"],
        request_timeout_seconds=DEFAULT_REQUEST_TIMEOUT_SECONDS,
    )
    for name, target in TARGETS.items()
}


SQLI_PAYLOADS = [
    "1",
    "1 OR 1=1",
    "'",
    "%27 OR %271%27=%271",
]

XSS_PAYLOADS = [
    "test",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<ScRiPt>alert(1)</ScRiPt>",
]

BRUTE_FORCE_PASSWORDS = [
    "wrongpass",
    "password1",
    "admin123",
    "letmein",
    "incorrect-password",
]

BACKGROUND_PATHS = [
    "/login.php",
    "/index.php",
    "/security.php",
    "/vulnerabilities/sqli/",
    "/vulnerabilities/xss_r/",
    "/vulnerabilities/weak_id/",
    "/vulnerabilities/javascript/",
]

CSV_COLUMNS = [
    "timestamp",
    "run_id",
    "environment",
    "waf_type",
    "phase",
    "load_level",
    "traffic_type",
    "attack_type",
    "request_name",
    "method",
    "url",
    "status_code",
    "result",
    "response_time_ms",
    "blocked_flag",
    "allowed_flag",
    "redirect_flag",
    "client_error_flag",
    "server_error_flag",
    "timeout_flag",
    "zap_alert_count",
    "zap_high_alert_count",
    "zap_medium_alert_count",
    "zap_low_alert_count",
]
