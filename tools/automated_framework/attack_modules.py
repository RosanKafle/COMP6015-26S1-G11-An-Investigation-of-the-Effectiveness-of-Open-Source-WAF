"""Controlled DVWA request and attack modules.

The attack modules never target ZAP's API URL. They build every application URL
from the selected DVWA base_url and optionally route traffic through ZAP_PROXY.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import time
from typing import Dict, Iterator, List, Optional
from urllib.parse import urljoin

import requests

from config import (
    DEFAULT_SECURITY_LEVEL,
    DVWA_PASSWORD,
    DVWA_USERNAME,
    EnvironmentConfig,
)
from data_logger import RequestObservation, classify_result


TOKEN_INPUT_PATTERN = re.compile(
    r"<input[^>]*name=[\"']user_token[\"'][^>]*>", re.IGNORECASE
)
TOKEN_VALUE_PATTERN = re.compile(r"value=[\"']([^\"']+)[\"']", re.IGNORECASE)


ATTACK_DEFINITIONS = [
    {
        "attack_type": "sqli",
        "request_name": "sqli_safe_id_1",
        "method": "GET",
        "path": "/vulnerabilities/sqli/",
        "params": {"id": "1", "Submit": "Submit"},
        "data": None,
        "expected_behavior": "allowed",
    },
    {
        "attack_type": "sqli",
        "request_name": "sqli_or_1_equals_1",
        "method": "GET",
        "path": "/vulnerabilities/sqli/",
        "params": {"id": "1 OR 1=1", "Submit": "Submit"},
        "data": None,
        "expected_behavior": "blocked",
    },
    {
        "attack_type": "sqli",
        "request_name": "sqli_single_quote",
        "method": "GET",
        "path": "/vulnerabilities/sqli/",
        "params": {"id": "'", "Submit": "Submit"},
        "data": None,
        "expected_behavior": "blocked",
    },
    {
        "attack_type": "sqli",
        "request_name": "sqli_encoded_quote_or_true",
        "method": "GET",
        "path": "/vulnerabilities/sqli/?id=%27%20OR%20%271%27=%271&Submit=Submit",
        "params": None,
        "data": None,
        "expected_behavior": "blocked",
    },
    {
        "attack_type": "xss",
        "request_name": "xss_safe_name_test",
        "method": "GET",
        "path": "/vulnerabilities/xss_r/",
        "params": {"name": "test"},
        "data": None,
        "expected_behavior": "allowed",
    },
    {
        "attack_type": "xss",
        "request_name": "xss_script_alert",
        "method": "GET",
        "path": "/vulnerabilities/xss_r/",
        "params": {"name": "<script>alert(1)</script>"},
        "data": None,
        "expected_behavior": "blocked",
    },
    {
        "attack_type": "xss",
        "request_name": "xss_img_onerror",
        "method": "GET",
        "path": "/vulnerabilities/xss_r/",
        "params": {"name": "<img src=x onerror=alert(1)>"},
        "data": None,
        "expected_behavior": "blocked",
    },
    {
        "attack_type": "xss",
        "request_name": "xss_mixed_case_script",
        "method": "GET",
        "path": "/vulnerabilities/xss_r/",
        "params": {"name": "<ScRiPt>alert(1)</ScRiPt>"},
        "data": None,
        "expected_behavior": "blocked",
    },
    {
        "attack_type": "brute_force",
        "request_name": "brute_force_wrong_password_normal",
        "method": "GET",
        "path": "/vulnerabilities/brute/",
        "params": {"username": "admin", "password": "wrongpass", "Login": "Login"},
        "data": None,
        "expected_behavior": "allowed",
    },
    {
        "attack_type": "brute_force",
        "request_name": "brute_force_wrong_password_repeated_1",
        "method": "GET",
        "path": "/vulnerabilities/brute/",
        "params": {"username": "admin", "password": "password1", "Login": "Login"},
        "data": None,
        "expected_behavior": "blocked",
    },
    {
        "attack_type": "brute_force",
        "request_name": "brute_force_wrong_password_repeated_2",
        "method": "GET",
        "path": "/vulnerabilities/brute/",
        "params": {"username": "admin", "password": "admin123", "Login": "Login"},
        "data": None,
        "expected_behavior": "blocked",
    },
    {
        "attack_type": "brute_force",
        "request_name": "brute_force_sqli_username",
        "method": "GET",
        "path": "/vulnerabilities/brute/",
        "params": {
            "username": "admin' OR '1'='1",
            "password": "wrongpass",
            "Login": "Login",
        },
        "data": None,
        "expected_behavior": "blocked",
    },
    {
        "attack_type": "brute_force",
        "request_name": "brute_force_xss_username",
        "method": "GET",
        "path": "/vulnerabilities/brute/",
        "params": {
            "username": "<script>alert(1)</script>",
            "password": "wrongpass",
            "Login": "Login",
        },
        "data": None,
        "expected_behavior": "blocked",
    },
    {
        "attack_type": "csrf",
        "request_name": "csrf_page_visit",
        "method": "GET",
        "path": "/vulnerabilities/csrf/",
        "params": None,
        "data": None,
        "expected_behavior": "allowed",
    },
    {
        "attack_type": "csrf",
        "request_name": "csrf_controlled_password_change_mismatch",
        "method": "GET",
        "path": "/vulnerabilities/csrf/",
        "params": {
            "password_new": "password",
            "password_conf": "not_the_same",
            "Change": "Change",
        },
        "data": None,
        "expected_behavior": "observed",
    },
    {
        "attack_type": "javascript",
        "request_name": "javascript_page_visit",
        "method": "GET",
        "path": "/vulnerabilities/javascript/",
        "params": None,
        "data": None,
        "expected_behavior": "allowed",
    },
    {
        "attack_type": "javascript",
        "request_name": "javascript_expected_input",
        "method": "GET",
        "path": "/vulnerabilities/javascript/",
        "params": {"phrase": "success", "send": "Submit"},
        "data": None,
        "expected_behavior": "allowed",
    },
    {
        "attack_type": "javascript",
        "request_name": "javascript_tampered_input",
        "method": "GET",
        "path": "/vulnerabilities/javascript/",
        "params": {"phrase": "<script>alert(1)</script>", "token": "tampered"},
        "data": None,
        "expected_behavior": "observed",
    },
    {
        "attack_type": "weak_session_ids",
        "request_name": "weak_session_ids_page_visit_1",
        "method": "GET",
        "path": "/vulnerabilities/weak_id/",
        "params": None,
        "data": None,
        "expected_behavior": "observed",
    },
    {
        "attack_type": "weak_session_ids",
        "request_name": "weak_session_ids_page_visit_2",
        "method": "GET",
        "path": "/vulnerabilities/weak_id/",
        "params": None,
        "data": None,
        "expected_behavior": "observed",
    },
    {
        "attack_type": "weak_session_ids",
        "request_name": "weak_session_ids_generate",
        "method": "GET",
        "path": "/vulnerabilities/weak_id/",
        "params": {"Generate": "Generate"},
        "data": None,
        "expected_behavior": "observed",
    },
    {
        "attack_type": "authorization_bypass",
        "request_name": "authorization_bypass_page_visit",
        "method": "GET",
        "path": "/vulnerabilities/authbypass/",
        "params": None,
        "data": None,
        "expected_behavior": "observed",
    },
    {
        "attack_type": "authorization_bypass",
        "request_name": "authorization_bypass_controlled_admin_hint",
        "method": "GET",
        "path": "/vulnerabilities/authbypass/",
        "params": {"user": "admin", "role": "admin", "debug": "true"},
        "data": None,
        "expected_behavior": "blocked",
    },
]


def extract_user_token(html: str) -> Optional[str]:
    input_match = TOKEN_INPUT_PATTERN.search(html)
    if not input_match:
        return None
    value_match = TOKEN_VALUE_PATTERN.search(input_match.group(0))
    return value_match.group(1) if value_match else None


def contains_dvwa_login_form(html: str) -> bool:
    lowered = html.lower()
    return all(
        field in lowered for field in ("username", "password", "login", "user_token")
    )


def looks_like_zap_response(html: str) -> bool:
    lowered = html.lower()
    return "owasp zap" in lowered or "zed attack proxy" in lowered or "zap api" in lowered


@dataclass(frozen=True)
class PreparedRequest:
    method: str
    path: str
    traffic_type: str
    attack_type: str
    request_name: str
    phase: str = "attack"
    load_level: str = "concurrent"
    params: Optional[Dict[str, str]] = None
    data: Optional[Dict[str, str]] = None
    expected_behavior: str = "observed"
    allow_redirects: bool = False


@dataclass(frozen=True)
class MeasuredResponse:
    observation: RequestObservation
    response: Optional[requests.Response]


class DVWAClient:
    """Authenticated DVWA client used by attacks and benign traffic."""

    def __init__(
        self,
        environment: EnvironmentConfig,
        run_id: str,
        proxies: Optional[Dict[str, str]] = None,
        debug: bool = False,
    ) -> None:
        self.environment = environment
        self.run_id = run_id
        self.debug = debug
        self.base_url = environment.base_url.rstrip("/") + "/"
        self.timeout = environment.request_timeout_seconds
        self.session = requests.Session()
        self.session.trust_env = False
        if proxies:
            self.session.proxies.update(proxies)
        self.session.headers.update(self._headers("benign", "none", "session_init"))

    def absolute_url(self, path: str) -> str:
        return urljoin(self.base_url, path.lstrip("/"))

    def perform(self, prepared: PreparedRequest) -> MeasuredResponse:
        url = self.absolute_url(prepared.path)
        start = time.perf_counter()
        try:
            response = self.session.request(
                prepared.method,
                url,
                params=prepared.params,
                data=prepared.data,
                headers=self._headers(
                    prepared.traffic_type,
                    prepared.attack_type,
                    prepared.request_name,
                ),
                timeout=self.timeout,
                allow_redirects=prepared.allow_redirects,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            status_code = response.status_code
            result = classify_result(status_code)
            if status_code == 404:
                status_code = 0
                result = "endpoint_missing"
            return MeasuredResponse(
                observation=RequestObservation(
                    phase=prepared.phase,
                    load_level=prepared.load_level,
                    traffic_type=prepared.traffic_type,
                    attack_type=prepared.attack_type,
                    request_name=prepared.request_name,
                    method=prepared.method,
                    url=response.url,
                    status_code=status_code,
                    result=result,
                    response_time_ms=elapsed_ms,
                    expected_behavior=prepared.expected_behavior,
                ),
                response=response,
            )
        except requests.Timeout as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return MeasuredResponse(
                observation=RequestObservation(
                    phase=prepared.phase,
                    load_level=prepared.load_level,
                    traffic_type=prepared.traffic_type,
                    attack_type=prepared.attack_type,
                    request_name=prepared.request_name,
                    method=prepared.method,
                    url=url,
                    status_code=0,
                    result="timeout",
                    response_time_ms=elapsed_ms,
                    expected_behavior=prepared.expected_behavior,
                    timeout=True,
                    error=str(exc),
                ),
                response=None,
            )
        except requests.RequestException as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return MeasuredResponse(
                observation=RequestObservation(
                    phase=prepared.phase,
                    load_level=prepared.load_level,
                    traffic_type=prepared.traffic_type,
                    attack_type=prepared.attack_type,
                    request_name=prepared.request_name,
                    method=prepared.method,
                    url=url,
                    status_code=0,
                    result="unknown",
                    response_time_ms=elapsed_ms,
                    expected_behavior=prepared.expected_behavior,
                    error=str(exc),
                ),
                response=None,
            )

    def request(self, prepared: PreparedRequest) -> RequestObservation:
        return self.perform(prepared).observation

    def login(self, username: str, password: str) -> tuple[bool, List[RequestObservation]]:
        observations: List[RequestObservation] = []

        login_get = self.perform(
            PreparedRequest(
                method="GET",
                path="/login.php",
                phase="setup",
                load_level="setup",
                traffic_type="benign",
                attack_type="none",
                request_name="login_get",
            )
        )
        observations.append(login_get.observation)
        token = extract_user_token(login_get.response.text) if login_get.response else None

        payload = {"username": username, "password": password, "Login": "Login"}
        if token:
            payload["user_token"] = token

        login_post = self.perform(
            PreparedRequest(
                method="POST",
                path="/login.php",
                phase="setup",
                load_level="setup",
                traffic_type="benign",
                attack_type="none",
                request_name="login_post",
                data=payload,
            )
        )
        observations.append(login_post.observation)

        verify_get = self.perform(
            PreparedRequest(
                method="GET",
                path="/index.php",
                phase="setup",
                load_level="setup",
                traffic_type="benign",
                attack_type="none",
                request_name="login_verify_index",
            )
        )
        observations.append(verify_get.observation)

        valid = self._login_is_valid(verify_get.response)
        if not valid:
            self._print_login_debug(
                login_get.response, login_post.response, verify_get.response
            )
        return valid, observations

    def set_security_level(self, level: str) -> tuple[bool, List[RequestObservation]]:
        observations: List[RequestObservation] = []

        security_get = self.perform(
            PreparedRequest(
                method="GET",
                path="/security.php",
                phase="setup",
                load_level="setup",
                traffic_type="benign",
                attack_type="none",
                request_name="security_get",
            )
        )
        observations.append(security_get.observation)
        token = extract_user_token(security_get.response.text) if security_get.response else None

        payload = {"security": level, "seclev_submit": "Submit"}
        if token:
            payload["user_token"] = token

        security_post = self.perform(
            PreparedRequest(
                method="POST",
                path="/security.php",
                phase="setup",
                load_level="setup",
                traffic_type="benign",
                attack_type="none",
                request_name="security_post",
                data=payload,
            )
        )
        observations.append(security_post.observation)

        security_verify = self.perform(
            PreparedRequest(
                method="GET",
                path="/security.php",
                phase="setup",
                load_level="setup",
                traffic_type="benign",
                attack_type="none",
                request_name="security_verify",
            )
        )
        observations.append(security_verify.observation)

        cookie_matches = self.session.cookies.get("security") == level
        page_confirms = self._security_page_confirms_level(security_verify.response, level)
        return cookie_matches or page_confirms, observations

    def prepare_authenticated_session(
        self,
        username: str = DVWA_USERNAME,
        password: str = DVWA_PASSWORD,
        security_level: str = DEFAULT_SECURITY_LEVEL,
    ) -> List[RequestObservation]:
        observations: List[RequestObservation] = []
        login_ok, login_observations = self.login(username, password)
        observations.extend(login_observations)
        if not login_ok:
            raise RuntimeError(
                f"DVWA login failed for {self.environment.name} at {self.environment.base_url}"
            )

        security_ok, security_observations = self.set_security_level(security_level)
        observations.extend(security_observations)
        if not security_ok:
            raise RuntimeError(
                f"Could not set DVWA security level to {security_level} for {self.environment.name}"
            )
        return observations

    def _headers(
        self, traffic_type: str, attack_type: str, request_name: str
    ) -> Dict[str, str]:
        user_agent_prefix = (
            "WAF-Eval-Benign" if traffic_type == "benign" else "WAF-Eval-Framework"
        )
        return {
            "X-WAF-Test-ID": self.run_id,
            "X-WAF-Test-Environment": self.environment.name,
            "X-WAF-Traffic-Type": traffic_type,
            "X-WAF-Attack-Type": attack_type,
            "X-WAF-Request-Name": request_name,
            "User-Agent": f"{user_agent_prefix}/{self.run_id}",
        }

    def _login_is_valid(self, response: Optional[requests.Response]) -> bool:
        if response is None or response.status_code != 200:
            return False
        text = response.text
        return "dvwa" in text.lower() and not contains_dvwa_login_form(text)

    def _security_page_confirms_level(
        self, response: Optional[requests.Response], level: str
    ) -> bool:
        if response is None or response.status_code != 200:
            return False
        text = response.text.lower()
        selected_option = re.search(
            rf'value=["\']{re.escape(level.lower())}["\'][^>]*selected', text
        )
        return bool(selected_option) or f"security level is currently: {level.lower()}" in text

    def _print_login_debug(
        self,
        login_get: Optional[requests.Response],
        login_post: Optional[requests.Response],
        verify_get: Optional[requests.Response],
    ) -> None:
        post_response = login_post or verify_get or login_get
        redirect_location = ""
        if login_post is not None:
            redirect_location = login_post.headers.get("Location", "")
        body = post_response.text[:500] if post_response is not None else ""

        print("DVWA login failed debug information:")
        print(f"Login GET status: {_status(login_get)}")
        print(f"Login POST status: {_status(login_post)}")
        print(f"Redirect location: {redirect_location}")
        print(f"First 500 chars of response: {body}")
        print(f"Cookies stored in session: {self.session.cookies.get_dict()}")


class AttackExecutor:
    """Generates controlled payload traffic against DVWA."""

    def __init__(
        self,
        environment: EnvironmentConfig,
        run_id: str,
        phase: str,
        load_level: str,
        proxies: Optional[Dict[str, str]] = None,
        username: str = DVWA_USERNAME,
        password: str = DVWA_PASSWORD,
        security_level: str = DEFAULT_SECURITY_LEVEL,
        debug: bool = False,
    ) -> None:
        self.environment = environment
        self.proxies = proxies
        self.username = username
        self.password = password
        self.security_level = security_level
        self.phase = phase
        self.load_level = load_level
        self.client = DVWAClient(environment, run_id=run_id, proxies=proxies, debug=debug)

    def prepare(self) -> List[RequestObservation]:
        return self.client.prepare_authenticated_session(
            self.username, self.password, self.security_level
        )

    def run_attack_cycle(self) -> Iterator[RequestObservation]:
        for definition in ATTACK_DEFINITIONS:
            yield self.client.request(
                PreparedRequest(
                    method=definition["method"],
                    path=definition["path"],
                    traffic_type="attack",
                    attack_type=definition["attack_type"],
                    request_name=definition["request_name"],
                    phase=self.phase,
                    load_level=self.load_level,
                    params=definition.get("params"),
                    data=definition.get("data"),
                    expected_behavior=definition.get("expected_behavior", "observed"),
                )
            )


def _status(response: Optional[requests.Response]) -> str:
    return str(response.status_code) if response is not None else "no response"
