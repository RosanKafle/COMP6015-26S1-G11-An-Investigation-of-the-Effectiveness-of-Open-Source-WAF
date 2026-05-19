"""CLI runner for controlled WAF effectiveness experiments."""

from __future__ import annotations

import argparse
from dataclasses import replace
import getpass
from pathlib import Path
import sys
import time
from typing import Dict, Optional

import requests

from attack_modules import (
    AttackExecutor,
    contains_dvwa_login_form,
    looks_like_zap_response,
)
from config import (
    ATTACK_DELAY_SECONDS,
    DEFAULT_SECURITY_LEVEL,
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    DVWA_PASSWORD,
    DVWA_USERNAME,
    ENVIRONMENTS,
    LOAD_PROFILES,
    MIXED_PHASE_WARMUP_SECONDS,
    TARGETS,
    ZAP_API,
    ZAP_API_KEY,
    ZAP_PROXY,
)
from data_logger import CSVDataLogger, RequestObservation
from output_manager import (
    build_metadata,
    confirm_environment_ready,
    make_run_id,
    resolve_run_paths,
    run_remote_state_check,
    utc_now,
    validate_run,
    write_metadata,
    write_validation,
)
from summary_writer import print_console_summary, write_run_outputs
from traffic_generator import BackgroundTrafficGenerator
from zap_controller import ZAPController, make_zap_session_name


PHASES = ("attack_only", "benign_only", "mixed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run reproducible DVWA WAF evaluation experiments."
    )
    parser.add_argument(
        "--env",
        required=True,
        choices=sorted(TARGETS.keys()),
        help="Experimental environment to test.",
    )
    parser.add_argument(
        "--phase",
        choices=PHASES,
        default="attack_only",
        help="Traffic phase to run. Default: attack_only.",
    )
    parser.add_argument(
        "--load-level",
        choices=sorted(LOAD_PROFILES.keys()),
        default="none",
        help="Benign live-traffic load level. Default: none.",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=120,
        help="Experiment duration in seconds. Default: 120.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Legacy detailed CSV path. Prefer --output-root for structured outputs.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("output"),
        help="Root directory for structured experiment outputs. Default: output.",
    )
    parser.add_argument(
        "--repetition",
        type=int,
        default=None,
        help="Optional repetition number appended to run_id as _rN.",
    )
    parser.add_argument(
        "--use-zap-proxy",
        action="store_true",
        help="Route generated DVWA HTTP traffic through ZAP_PROXY.",
    )
    parser.add_argument(
        "--enable-zap-alert-lookup",
        dest="zap_alert_lookup",
        action="store_true",
        help="Query ZAP alert counts after each generated request.",
    )
    parser.add_argument(
        "--disable-zap-alert-lookup",
        dest="zap_alert_lookup",
        action="store_false",
        help="Disable per-request ZAP alert lookup.",
    )
    parser.set_defaults(zap_alert_lookup=False)
    parser.add_argument(
        "--no-spider",
        action="store_true",
        help="Skip the initial ZAP spider phase.",
    )
    parser.add_argument(
        "--skip-spider",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print additional connection and DVWA login diagnostics.",
    )
    parser.add_argument(
        "--spider-timeout",
        type=int,
        default=120,
        help="Maximum seconds to wait for ZAP spider completion.",
    )
    parser.add_argument(
        "--zap-api",
        default=ZAP_API,
        help="Override the configured ZAP API endpoint.",
    )
    parser.add_argument(
        "--zap-proxy",
        default=ZAP_PROXY,
        help="Override the configured ZAP proxy endpoint.",
    )
    parser.add_argument(
        "--zap-api-key",
        default=ZAP_API_KEY,
        help="Override the configured ZAP API key.",
    )
    parser.add_argument(
        "--allow-zap-target",
        action="store_true",
        help="Allow a DVWA target that points at 127.0.0.1:8080 for non-standard labs.",
    )
    parser.add_argument(
        "--assume-ready",
        action="store_true",
        help="Skip the interactive WAF-state confirmation prompt.",
    )
    parser.add_argument(
        "--remote-host",
        default=None,
        help="Ubuntu host for optional remote WAF-state checks.",
    )
    parser.add_argument(
        "--remote-user",
        default=None,
        help="SSH user for optional remote WAF-state checks.",
    )
    parser.add_argument(
        "--remote-password",
        default=None,
        help="SSH/sudo password for optional remote WAF-state checks. Omit to prompt securely.",
    )
    parser.add_argument(
        "--check-remote-state",
        action="store_true",
        help="Run SSH checks to confirm the expected WAF state.",
    )
    parser.add_argument(
        "--attack-delay",
        type=float,
        default=ATTACK_DELAY_SECONDS,
        help="Seconds between controlled payload requests.",
    )
    return parser.parse_args()


def run_experiment(args: argparse.Namespace) -> Path:
    environment = ENVIRONMENTS[args.env]
    target = environment.base_url
    waf_type = environment.waf_type
    zap_api = args.zap_api.rstrip("/")
    zap_proxy = args.zap_proxy.rstrip("/")
    run_id = make_run_id(args.repetition)
    paths = resolve_run_paths(
        args.output_root,
        args.env,
        args.phase,
        args.load_level,
        run_id,
        legacy_output=args.output,
    )
    run_id = paths["run_id"]
    timestamp_start = utc_now()
    request_proxies = make_request_proxies(zap_proxy, args.use_zap_proxy)
    load_profile = LOAD_PROFILES[args.load_level]

    state_confirmed = confirm_environment_ready(environment, args.assume_ready)
    if not state_confirmed:
        raise RuntimeError("Expected WAF state was not confirmed.")
    remote_state = None
    if args.check_remote_state:
        if not args.remote_host:
            raise ValueError("--remote-host is required with --check-remote-state")
        remote_password = args.remote_password
        if remote_password is None:
            remote_password = getpass.getpass("SSH password for remote state check: ")
        remote_state = run_remote_state_check(
            args.env,
            args.remote_host,
            args.remote_user or "",
            remote_password=remote_password,
        )
        if not remote_state.get("confirmed"):
            print("Warning: remote WAF-state check did not confirm the expected state.")

    print_startup_banner(
        args.env, waf_type, target, zap_api, zap_proxy, args.phase, args.load_level
    )
    print(f"Run ID: {run_id}")
    print(f"Run directory: {paths['run_dir']}")
    validate_target_configuration(target, zap_api, allow_zap_target=args.allow_zap_target)

    zap = ZAPController(
        api_url=zap_api,
        api_key=args.zap_api_key,
        timeout_seconds=environment.request_timeout_seconds,
    )
    version = zap.connect()
    print(f"Connected to OWASP ZAP {version} at {zap_api}")

    sanity_check_dvwa_target(
        target,
        run_id=run_id,
        environment=args.env,
        proxies=request_proxies,
        debug=args.debug,
    )

    logger = CSVDataLogger(paths["detailed_csv"], run_id=run_id, reset=True)
    zap.new_session(make_zap_session_name(args.env))
    zap.access_url(target)

    if not (args.no_spider or args.skip_spider):
        print(f"Starting ZAP spider for {target}")
        zap.spider_target(target, timeout_seconds=args.spider_timeout)
        print("ZAP spider completed")

    background = build_background_generator(
        args,
        environment,
        logger,
        run_id,
        request_proxies,
        load_profile,
        zap,
        target,
    )

    deadline = time.monotonic() + args.duration
    attack_count = 0
    try:
        if args.phase in {"benign_only", "mixed"}:
            print(f"Starting benign traffic threads: {background.thread_count}")
            background.start()

        if args.phase == "mixed":
            warmup = min(MIXED_PHASE_WARMUP_SECONDS, max(args.duration, 0))
            if warmup > 0:
                time.sleep(warmup)

        if args.phase in {"attack_only", "mixed"}:
            print("Starting controlled attacks")
            attack_count = run_controlled_attacks(
                args,
                environment,
                logger,
                zap,
                target,
                run_id,
                request_proxies,
                deadline,
            )
        else:
            sleep_until(deadline)
    finally:
        background.stop()
        background.join(timeout=5)

    summary_path, json_path, run_summary = write_run_outputs(
        logger.rows(),
        paths["detailed_csv"],
        run_id,
        environment,
        args.phase,
        args.load_level,
        args.duration,
    )
    timestamp_end = utc_now()
    metadata = build_metadata(
        run_id,
        timestamp_start,
        timestamp_end,
        environment,
        args.phase,
        args.load_level,
        args.duration,
        target,
        zap_api,
        args.use_zap_proxy,
        state_confirmed,
        remote_state,
    )
    write_metadata(paths["metadata_json"], metadata)
    validation_passed, validation_checks = validate_run(
        paths["detailed_csv"],
        logger.rows(),
        args.phase,
        target,
        zap_api,
        metadata,
    )
    write_validation(paths["validation_txt"], validation_passed, validation_checks)
    print_console_summary(run_summary)
    print(f"Experiment complete. Attack requests logged: {attack_count}")
    print(f"Detailed results written to {paths['detailed_csv']}")
    print(f"Summary CSV written to {summary_path}")
    print(f"Run summary JSON written to {json_path}")
    print(f"Metadata written to {paths['metadata_json']}")
    print(f"Validation written to {paths['validation_txt']}")
    return paths["detailed_csv"]


def run_controlled_attacks(
    args: argparse.Namespace,
    environment,
    logger: CSVDataLogger,
    zap: ZAPController,
    target: str,
    run_id: str,
    request_proxies: Optional[Dict[str, str]],
    deadline: float,
) -> int:
    attack_executor = AttackExecutor(
        environment,
        run_id=run_id,
        phase=args.phase,
        load_level=args.load_level,
        proxies=request_proxies,
        username=DVWA_USERNAME,
        password=DVWA_PASSWORD,
        security_level=DEFAULT_SECURITY_LEVEL,
        debug=args.debug,
    )
    setup_observations = attack_executor.prepare()
    for observation in setup_observations:
        logger.log(environment, observation)
    print("DVWA login successful")
    print(f"DVWA security level set to {DEFAULT_SECURITY_LEVEL}")

    attack_count = 0
    while time.monotonic() < deadline:
        for observation in attack_executor.run_attack_cycle():
            observation = maybe_add_zap_alert_counts(
                observation,
                zap,
                target,
                enabled=args.zap_alert_lookup,
            )
            logger.log(environment, observation)
            attack_count += 1
            if time.monotonic() >= deadline:
                break
            time.sleep(args.attack_delay)
    return attack_count


def build_background_generator(
    args: argparse.Namespace,
    environment,
    logger: CSVDataLogger,
    run_id: str,
    request_proxies: Optional[Dict[str, str]],
    load_profile: dict,
    zap: ZAPController,
    target: str,
) -> BackgroundTrafficGenerator:
    thread_count = int(load_profile["threads"])
    if args.phase == "attack_only":
        thread_count = 0
    return BackgroundTrafficGenerator(
        environment,
        logger,
        run_id=run_id,
        phase=args.phase,
        load_level=args.load_level,
        thread_count=thread_count,
        delay_seconds=float(load_profile["delay"]),
        proxies=request_proxies,
        username=DVWA_USERNAME,
        password=DVWA_PASSWORD,
        security_level=DEFAULT_SECURITY_LEVEL,
        debug=args.debug,
        alert_counter=lambda observation: maybe_add_zap_alert_counts(
            observation,
            zap,
            target,
            enabled=args.zap_alert_lookup,
        ),
    )


def maybe_add_zap_alert_counts(
    observation: RequestObservation,
    zap: ZAPController,
    target: str,
    enabled: bool,
) -> RequestObservation:
    if not enabled:
        return observation
    try:
        counts = zap.alert_counts_for_url(observation.url, target)
    except requests.RequestException:
        return observation
    return replace(observation, **counts)


def sleep_until(deadline: float) -> None:
    while time.monotonic() < deadline:
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))


def print_startup_banner(
    environment: str,
    waf_type: str,
    target: str,
    zap_api: str,
    zap_proxy: str,
    phase: str,
    load_level: str,
) -> None:
    print(f"ZAP API endpoint: {zap_api}")
    print(f"ZAP proxy endpoint: {zap_proxy}")
    print(f"DVWA target: {target}")
    print(f"Environment: {environment}")
    print(f"WAF type: {waf_type}")
    print(f"Phase: {phase}")
    print(f"Load level: {load_level}")


def validate_target_configuration(
    target: str,
    zap_api: str,
    allow_zap_target: bool = False,
) -> None:
    normalized_target = target.rstrip("/")
    normalized_zap_api = zap_api.rstrip("/")
    if normalized_target.startswith(normalized_zap_api):
        raise ValueError("Invalid config: DVWA target is pointing to ZAP API endpoint")
    if "127.0.0.1:8080" in normalized_target and not allow_zap_target:
        raise ValueError(
            "Invalid config: DVWA target contains 127.0.0.1:8080, which is the ZAP endpoint"
        )


def sanity_check_dvwa_target(
    base_url: str,
    run_id: str,
    environment: str,
    proxies: Optional[Dict[str, str]],
    debug: bool = False,
) -> None:
    session = requests.Session()
    session.trust_env = False
    login_url = f"{base_url.rstrip('/')}/login.php"
    response = session.get(
        login_url,
        headers=request_headers(
            run_id, environment, "benign", "none", "sanity_login_page"
        ),
        proxies=proxies,
        timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS,
        allow_redirects=False,
    )

    if looks_like_zap_response(response.text):
        raise ValueError(
            "Target misconfiguration: application target appears to be ZAP, not DVWA."
        )
    if not contains_dvwa_login_form(response.text):
        if debug:
            print(f"DVWA target check status: {response.status_code}")
            print(f"DVWA target check first 500 chars: {response.text[:500]}")
        raise ValueError(
            "Target misconfiguration: DVWA login form fields were not found at "
            f"{login_url}"
        )
    if debug:
        print(f"DVWA target check status: {response.status_code}")


def request_headers(
    run_id: str,
    environment: str,
    traffic_type: str,
    attack_type: str,
    request_name: str,
) -> Dict[str, str]:
    user_agent_prefix = (
        "WAF-Eval-Benign" if traffic_type == "benign" else "WAF-Eval-Framework"
    )
    return {
        "X-WAF-Test-ID": run_id,
        "X-WAF-Test-Environment": environment,
        "X-WAF-Traffic-Type": traffic_type,
        "X-WAF-Attack-Type": attack_type,
        "X-WAF-Request-Name": request_name,
        "User-Agent": f"{user_agent_prefix}/{run_id}",
    }


def make_request_proxies(
    zap_proxy: str,
    use_zap_proxy: bool,
) -> Optional[Dict[str, str]]:
    if not use_zap_proxy:
        return None
    return {"http": zap_proxy, "https": zap_proxy}


def main() -> int:
    args = parse_args()
    if args.duration <= 0:
        print("--duration must be greater than zero", file=sys.stderr)
        return 2
    try:
        run_experiment(args)
        return 0
    except KeyboardInterrupt:
        print("Experiment interrupted by user.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Experiment failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
