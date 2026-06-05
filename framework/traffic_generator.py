"""Concurrent benign traffic simulation for false-positive measurement."""

from __future__ import annotations

import itertools
import threading
from typing import Callable, Dict, Iterable, Optional

try:
    from .config import (
        DEFAULT_SECURITY_LEVEL,
        DVWA_PASSWORD,
        DVWA_USERNAME,
        EnvironmentConfig,
    )
    from .attack_modules import DVWAClient, PreparedRequest
    from .data_logger import CSVDataLogger, RequestObservation
except ImportError:  # Supports: python framework/traffic_generator.py
    from config import (
        DEFAULT_SECURITY_LEVEL,
        DVWA_PASSWORD,
        DVWA_USERNAME,
        EnvironmentConfig,
    )
    from attack_modules import DVWAClient, PreparedRequest
    from data_logger import CSVDataLogger, RequestObservation


BENIGN_REQUESTS = [
    {
        "request_name": "benign_login_page",
        "method": "GET",
        "path": "/login.php",
        "params": None,
    },
    {
        "request_name": "benign_index_page",
        "method": "GET",
        "path": "/index.php",
        "params": None,
    },
    {
        "request_name": "benign_security_page",
        "method": "GET",
        "path": "/security.php",
        "params": None,
    },
    {
        "request_name": "benign_sqli_safe_id_1",
        "method": "GET",
        "path": "/vulnerabilities/sqli/",
        "params": {"id": "1", "Submit": "Submit"},
    },
    {
        "request_name": "benign_sqli_safe_id_2",
        "method": "GET",
        "path": "/vulnerabilities/sqli/",
        "params": {"id": "2", "Submit": "Submit"},
    },
    {
        "request_name": "benign_xss_safe_name_alice",
        "method": "GET",
        "path": "/vulnerabilities/xss_r/",
        "params": {"name": "Alice"},
    },
    {
        "request_name": "benign_xss_safe_name_test",
        "method": "GET",
        "path": "/vulnerabilities/xss_r/",
        "params": {"name": "test"},
    },
    {
        "request_name": "benign_weak_session_page",
        "method": "GET",
        "path": "/vulnerabilities/weak_id/",
        "params": None,
    },
    {
        "request_name": "benign_javascript_page",
        "method": "GET",
        "path": "/vulnerabilities/javascript/",
        "params": None,
    },
]


class BackgroundTrafficGenerator:
    """Generate normal DVWA browsing traffic while attacks are running."""

    def __init__(
        self,
        environment: EnvironmentConfig,
        logger: CSVDataLogger,
        run_id: str,
        phase: str,
        load_level: str,
        thread_count: int,
        delay_seconds: float,
        proxies: Optional[Dict[str, str]] = None,
        requests_plan: Iterable[dict] = BENIGN_REQUESTS,
        username: str = DVWA_USERNAME,
        password: str = DVWA_PASSWORD,
        security_level: str = DEFAULT_SECURITY_LEVEL,
        debug: bool = False,
        alert_counter: Optional[Callable[[RequestObservation], RequestObservation]] = None,
    ) -> None:
        self.environment = environment
        self.logger = logger
        self.run_id = run_id
        self.phase = phase
        self.load_level = load_level
        self.thread_count = thread_count
        self.delay_seconds = delay_seconds
        self.proxies = proxies
        self.requests_plan = list(requests_plan)
        self.username = username
        self.password = password
        self.security_level = security_level
        self.debug = debug
        self.alert_counter = alert_counter
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        if self.thread_count <= 0:
            return
        for worker_id in range(1, self.thread_count + 1):
            thread = threading.Thread(
                target=self._run,
                args=(worker_id,),
                name=f"benign-{self.environment.name}-{worker_id}",
                daemon=True,
            )
            self._threads.append(thread)
            thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def join(self, timeout: Optional[float] = None) -> None:
        for thread in self._threads:
            thread.join(timeout=timeout)

    def _new_client(self) -> DVWAClient:
        return DVWAClient(
            self.environment,
            run_id=self.run_id,
            proxies=self.proxies,
            debug=self.debug,
        )

    def _prepare(self, client: DVWAClient) -> None:
        try:
            observations = client.prepare_authenticated_session(
                self.username, self.password, self.security_level
            )
            for observation in observations:
                if self.alert_counter:
                    observation = self.alert_counter(observation)
                self.logger.log(self.environment, observation)
        except Exception:
            # If DVWA authentication is unavailable, redirects/errors are still
            # useful benign observations and will be logged below.
            return

    def _run(self, worker_id: int) -> None:
        client = self._new_client()
        self._prepare(client)
        for index, definition in enumerate(itertools.cycle(self.requests_plan), start=1):
            if self._stop_event.is_set():
                return
            request_name = f"{definition['request_name']}_t{worker_id}_{index}"
            observation = client.request(
                PreparedRequest(
                    method=definition["method"],
                    path=definition["path"],
                    phase=self.phase,
                    load_level=self.load_level,
                    traffic_type="benign",
                    attack_type="none",
                    request_name=request_name,
                    params=definition.get("params"),
                    data=definition.get("data"),
                )
            )
            if self.alert_counter:
                observation = self.alert_counter(observation)
            self.logger.log(self.environment, observation)
            self._stop_event.wait(self.delay_seconds)
