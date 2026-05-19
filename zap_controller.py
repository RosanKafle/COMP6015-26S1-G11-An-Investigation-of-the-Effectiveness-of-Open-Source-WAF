"""OWASP ZAP REST API integration.

ZAP control traffic goes to ZAP_API only. Application traffic is sent to the
DVWA target URL, optionally through ZAP_PROXY when --use-zap-proxy is enabled.
"""

from __future__ import annotations

from datetime import datetime, timezone
import threading
import time
from typing import Dict, List, Optional
from urllib.parse import quote, urlparse

import requests


ATTACK_ALERT_KEYWORDS = {
    "sqli": ("sql injection", "sql", "database"),
    "xss": ("cross site scripting", "xss", "script"),
    "brute_force": ("authentication", "brute force", "password", "credential"),
    "csrf": ("csrf", "cross-site request forgery"),
    "javascript": ("script", "javascript"),
    "weak_session_ids": ("session", "cookie"),
    "authorization_bypass": ("authorization", "authentication", "access control"),
}


class ZAPController:
    """Small direct wrapper around the ZAP JSON API."""

    def __init__(self, api_url: str, api_key: str = "", timeout_seconds: float = 10.0):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self._api_session = requests.Session()
        self._api_session.trust_env = False
        self._lock = threading.Lock()

    def connect(self) -> str:
        return self.version()

    def version(self) -> str:
        payload = self._api_get("/JSON/core/view/version/")
        return str(payload.get("version", "unknown"))

    def new_session(self, session_name: str) -> None:
        self._api_get(
            "/JSON/core/action/newSession/",
            {"name": session_name, "overwrite": "true"},
        )

    def access_url(self, target_url: str) -> None:
        self._api_get(
            "/JSON/core/action/accessUrl/",
            {"url": target_url, "followRedirects": "true"},
        )

    def start_spider(self, target_url: str) -> str:
        payload = self._api_get("/JSON/spider/action/scan/", {"url": target_url})
        scan_id = payload.get("scan")
        if scan_id is None:
            raise RuntimeError(f"ZAP spider did not return a scan id: {payload}")
        return str(scan_id)

    def wait_for_spider(
        self,
        scan_id: str,
        timeout_seconds: int = 120,
        poll_interval_seconds: float = 2.0,
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            payload = self._api_get("/JSON/spider/view/status/", {"scanId": scan_id})
            status = int(payload.get("status", 0))
            if status >= 100:
                return
            time.sleep(poll_interval_seconds)
        raise TimeoutError(f"ZAP spider scan {scan_id} did not finish in time.")

    def spider_target(self, target_url: str, timeout_seconds: int = 120) -> None:
        scan_id = self.start_spider(target_url)
        self.wait_for_spider(scan_id, timeout_seconds=timeout_seconds)

    def start_active_scan(self, target_url: str) -> str:
        payload = self._api_get("/JSON/ascan/action/scan/", {"url": target_url})
        scan_id = payload.get("scan")
        if scan_id is None:
            raise RuntimeError(f"ZAP active scan did not return a scan id: {payload}")
        return str(scan_id)

    def wait_for_active_scan(
        self,
        scan_id: str,
        timeout_seconds: int = 600,
        poll_interval_seconds: float = 5.0,
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            payload = self._api_get("/JSON/ascan/view/status/", {"scanId": scan_id})
            status = int(payload.get("status", 0))
            if status >= 100:
                return
            time.sleep(poll_interval_seconds)
        raise TimeoutError(f"ZAP active scan {scan_id} did not finish in time.")

    def get_alerts(self, base_url: Optional[str] = None) -> List[dict]:
        """Retrieve alerts using /JSON/core/view/alerts/ as required."""

        params = {}
        if base_url:
            params["baseurl"] = base_url
        payload = self._api_get("/JSON/core/view/alerts/", params)
        alerts = payload.get("alerts", [])
        return alerts if isinstance(alerts, list) else []

    def alert_counts_for_url(self, request_url: str, base_url: str) -> dict:
        """Return total and risk-level alert counts for one request URL."""

        counts = {
            "zap_alert_count": 0,
            "zap_high_alert_count": 0,
            "zap_medium_alert_count": 0,
            "zap_low_alert_count": 0,
        }
        alerts = self.get_alerts(base_url=base_url)
        for alert in alerts:
            alert_url = str(alert.get("url", ""))
            if alert_url and not self._same_path_or_full_url(alert_url, request_url):
                continue
            counts["zap_alert_count"] += 1
            risk = str(alert.get("risk", "")).strip().lower()
            if risk == "high":
                counts["zap_high_alert_count"] += 1
            elif risk == "medium":
                counts["zap_medium_alert_count"] += 1
            elif risk == "low":
                counts["zap_low_alert_count"] += 1
        return counts

    def wait_for_relevant_alert(
        self,
        request_url: str,
        attack_type: str,
        base_url: str,
        wait_seconds: float = 2.0,
    ) -> bool:
        """Poll briefly for an alert that matches the request and attack type."""

        if attack_type not in ATTACK_ALERT_KEYWORDS:
            return False
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() <= deadline:
            try:
                if self.has_relevant_alert(request_url, attack_type, base_url):
                    return True
            except requests.RequestException:
                return False
            time.sleep(0.25)
        return False

    def has_relevant_alert(self, request_url: str, attack_type: str, base_url: str) -> bool:
        alerts = self.get_alerts(base_url=base_url)
        return any(
            self._alert_matches_request(alert, request_url, attack_type)
            for alert in alerts
        )

    def _api_get(self, path: str, params: Optional[Dict[str, str]] = None) -> dict:
        query = dict(params or {})
        if self.api_key:
            query["apikey"] = self.api_key
        with self._lock:
            response = self._api_session.get(
                f"{self.api_url}{path}", params=query, timeout=self.timeout_seconds
            )
        response.raise_for_status()
        return response.json()

    def _alert_matches_request(
        self, alert: dict, request_url: str, attack_type: str
    ) -> bool:
        alert_url = str(alert.get("url", ""))
        alert_text = " ".join(
            str(alert.get(key, ""))
            for key in ("alert", "name", "description", "param", "attack", "evidence")
        ).lower()
        keywords = ATTACK_ALERT_KEYWORDS.get(attack_type, ())
        if not any(keyword in alert_text for keyword in keywords):
            return False

        if not alert_url:
            return True
        return self._same_path_or_full_url(alert_url, request_url)

    @staticmethod
    def _same_path_or_full_url(alert_url: str, request_url: str) -> bool:
        if alert_url == request_url:
            return True
        parsed_alert = urlparse(alert_url)
        parsed_request = urlparse(request_url)
        return (
            parsed_alert.scheme == parsed_request.scheme
            and parsed_alert.netloc == parsed_request.netloc
            and parsed_alert.path == parsed_request.path
        )


def make_zap_session_name(environment: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_environment = quote(environment, safe="")
    return f"waf-eval-{safe_environment}-{timestamp}"
