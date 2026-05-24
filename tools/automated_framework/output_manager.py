"""Run directory, metadata, validation, and environment-state helpers."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
from typing import Optional

from config import DEFAULT_SECURITY_LEVEL, EnvironmentConfig


EXPECTED_STATE = {
    "baseline": {
        "label": "ModSecurity DISABLED",
        "instructions": "sudo a2dismod security2 && sudo systemctl restart apache2",
        "modsecurity_expected_state": "disabled",
        "coraza_expected_state": "not_used",
        "naxsi_expected_state": "not_used",
    },
    "modsec": {
        "label": "ModSecurity ENABLED",
        "instructions": "sudo a2enmod security2 && sudo systemctl restart apache2",
        "modsecurity_expected_state": "enabled",
        "coraza_expected_state": "not_used",
        "naxsi_expected_state": "not_used",
    },
    "coraza": {
        "label": "Coraza Docker container running",
        "instructions": "sudo docker ps | grep coraza-waf",
        "modsecurity_expected_state": "not_used",
        "coraza_expected_state": "running",
        "naxsi_expected_state": "not_used",
    },
    "naxsi": {
        "label": "NAXSI reverse proxy running",
        "instructions": "sudo docker ps | grep naxsi",
        "modsecurity_expected_state": "not_used",
        "coraza_expected_state": "not_used",
        "naxsi_expected_state": "running",
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def make_run_id(repetition: Optional[int] = None) -> str:
    base = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    if repetition is not None:
        return f"{base}_r{repetition}"
    return base


def resolve_run_paths(
    output_root: Path,
    environment: str,
    phase: str,
    load_level: str,
    run_id: str,
    legacy_output: Optional[Path] = None,
) -> dict:
    if legacy_output is not None:
        detailed_path = Path(legacy_output)
        run_dir = detailed_path.parent
        run_dir.mkdir(parents=True, exist_ok=True)
        return {
            "run_id": run_id,
            "run_dir": run_dir,
            "detailed_csv": detailed_path,
            "summary_csv": run_dir / "summary.csv",
            "run_summary_json": run_dir / "run_summary.json",
            "metadata_json": run_dir / "metadata.json",
            "validation_txt": run_dir / "validation.txt",
        }

    run_dir = Path(output_root) / environment / phase / load_level / f"run_{run_id}"
    if run_dir.exists():
        suffix = 1
        while (run_dir.parent / f"run_{run_id}_r{suffix}").exists():
            suffix += 1
        run_id = f"{run_id}_r{suffix}"
        run_dir = Path(output_root) / environment / phase / load_level / f"run_{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return {
        "run_id": run_id,
        "run_dir": run_dir,
        "detailed_csv": run_dir / "detailed.csv",
        "summary_csv": run_dir / "summary.csv",
        "run_summary_json": run_dir / "run_summary.json",
        "metadata_json": run_dir / "metadata.json",
        "validation_txt": run_dir / "validation.txt",
    }


def print_environment_checklist(environment: EnvironmentConfig) -> None:
    state = EXPECTED_STATE[environment.name]
    print(f"Environment selected: {environment.name}")
    print(f"Expected WAF state: {state['label']}")
    print(f"Target: {environment.base_url}")
    print("Before continuing, ensure on Ubuntu:")
    print(state["instructions"])


def confirm_environment_ready(environment: EnvironmentConfig, assume_ready: bool) -> bool:
    print_environment_checklist(environment)
    if assume_ready:
        return True
    answer = input("Have you confirmed the expected WAF state? Type YES to continue: ")
    return answer == "YES"


def run_remote_state_check(
    environment: str,
    remote_host: str,
    remote_user: str,
    remote_password: Optional[str] = None,
) -> dict:
    command = remote_command_for(environment, remote_password)
    if not command:
        return {
            "checked": False,
            "confirmed": False,
            "command": "",
            "stdout": "",
            "stderr": "No remote check is defined for this environment.",
            "returncode": None,
        }

    ssh_target = f"{remote_user}@{remote_host}" if remote_user else remote_host
    env = os.environ.copy()
    if remote_password:
        if not shutil.which("sshpass"):
            return {
                "checked": True,
                "confirmed": False,
                "command": command,
                "stdout": "",
                "stderr": "sshpass is required for --remote-password. Install it with: sudo apt install sshpass",
                "returncode": None,
                "password_auth_used": True,
            }
        env["SSHPASS"] = remote_password
        ssh_command = [
            "sshpass",
            "-e",
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            ssh_target,
            command,
        ]
    else:
        ssh_command = ["ssh", ssh_target, command]

    try:
        process = subprocess.run(
            ssh_command,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
            env=env,
        )
        stdout = process.stdout.strip()
        stderr = process.stderr.strip()
        returncode = process.returncode
    except (subprocess.SubprocessError, OSError) as exc:
        stdout = ""
        stderr = str(exc)
        returncode = None
    confirmed = remote_output_matches(environment, stdout, returncode)
    return {
        "checked": True,
        "confirmed": confirmed,
        "command": command,
        "stdout": stdout,
        "stderr": stderr,
        "returncode": returncode,
        "password_auth_used": bool(remote_password),
    }


def remote_command_for(environment: str, sudo_password: Optional[str] = None) -> str:
    if environment in {"baseline", "modsec"}:
        return "apache2ctl -M 2>/dev/null | grep security"
    if environment == "coraza":
        if sudo_password:
            return sudo_command("docker ps | grep coraza-waf", sudo_password)
        return "sudo docker ps | grep coraza-waf"
    if environment == "naxsi":
        if sudo_password:
            return sudo_command("docker ps | grep naxsi", sudo_password)
        return "sudo docker ps | grep naxsi"
    return ""


def sudo_command(command: str, password: str) -> str:
    quoted_password = shlex.quote(password)
    return f"printf '%s\\n' {quoted_password} | sudo -S {command}"


def remote_output_matches(environment: str, stdout: str, returncode: Optional[int]) -> bool:
    if environment == "baseline":
        return stdout == ""
    if environment == "modsec":
        return "security2_module" in stdout
    if environment == "coraza":
        return returncode == 0 and "coraza-waf" in stdout
    if environment == "naxsi":
        return returncode == 0 and "naxsi" in stdout.lower()
    return False


def build_metadata(
    run_id: str,
    timestamp_start: str,
    timestamp_end: str,
    environment: EnvironmentConfig,
    phase: str,
    load_level: str,
    duration_seconds: int,
    target_url: str,
    zap_api: str,
    zap_proxy_used: bool,
    state_confirmed: bool,
    remote_state: Optional[dict],
) -> dict:
    expected = EXPECTED_STATE[environment.name]
    return {
        "run_id": run_id,
        "timestamp_start": timestamp_start,
        "timestamp_end": timestamp_end,
        "environment": environment.name,
        "waf_type": environment.waf_type,
        "phase": phase,
        "load_level": load_level,
        "duration_seconds": duration_seconds,
        "target_url": target_url,
        "zap_api": zap_api,
        "zap_proxy_used": zap_proxy_used,
        "dvwa_security_level": DEFAULT_SECURITY_LEVEL,
        "modsecurity_expected_state": expected["modsecurity_expected_state"],
        "coraza_expected_state": expected["coraza_expected_state"],
        "naxsi_expected_state": expected["naxsi_expected_state"],
        "expected_waf_state_label": expected["label"],
        "manual_state_confirmed": state_confirmed,
        "remote_state_check": remote_state or {"checked": False, "confirmed": False},
    }


def write_metadata(path: Path, metadata: dict) -> None:
    path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")


def validate_run(
    detailed_csv: Path,
    rows: list[dict],
    phase: str,
    target_url: str,
    zap_api: str,
    metadata: dict,
) -> tuple[bool, list[tuple[str, bool, str]]]:
    checks = []
    checks.append(("CSV exists", detailed_csv.exists(), str(detailed_csv)))
    attack_required = phase in {"attack_only", "mixed"}
    attack_present = any(row.get("traffic_type") == "attack" for row in rows)
    checks.append(
        (
            "attack rows present",
            attack_present if attack_required else True,
            "required for attack_only and mixed phases",
        )
    )
    benign_required = phase in {"benign_only", "mixed"}
    benign_present = any(row.get("traffic_type") == "benign" for row in rows)
    checks.append(
        (
            "benign rows present when phase is benign_only or mixed",
            benign_present if benign_required else True,
            "not required for attack_only",
        )
    )
    statuses = [int_or_zero(row.get("status_code")) for row in rows]
    checks.append(("no all-302 failure", not statuses or any(code != 302 for code in statuses), ""))
    checks.append(
        (
            "response_time_ms present",
            bool(rows) and all(row.get("response_time_ms") not in {None, ""} for row in rows),
            "",
        )
    )
    checks.append(
        (
            "target does not point to ZAP API",
            not target_url.rstrip("/").startswith(zap_api.rstrip("/")),
            target_url,
        )
    )
    remote_state = metadata.get("remote_state_check", {})
    if remote_state.get("checked"):
        expected_confirmed = bool(remote_state.get("confirmed"))
        detail = "remote check"
    else:
        expected_confirmed = bool(metadata.get("manual_state_confirmed"))
        detail = "manual confirmation"
    checks.append(("expected WAF state confirmed", expected_confirmed, detail))
    return all(check[1] for check in checks), checks


def write_validation(path: Path, passed: bool, checks: list[tuple[str, bool, str]]) -> None:
    lines = [f"Run validation: {'PASS' if passed else 'FAIL'}", "", "Checks:"]
    for name, ok, detail in checks:
        suffix = f" - {detail}" if detail else ""
        lines.append(f"- {'PASS' if ok else 'FAIL'}: {name}{suffix}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def int_or_zero(value) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0
