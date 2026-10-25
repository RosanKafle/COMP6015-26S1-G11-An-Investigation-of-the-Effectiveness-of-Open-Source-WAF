"""Configuration for the inherited Kali -> local ZAP -> Ubuntu lab."""
import argparse
import json
import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit
from lab_http import validate_url

ROOT = Path(__file__).resolve().parents[1]
ENV_KEYS = {"TARGET_URL", "MODSECURITY_URL", "NAXSI_URL", "LAB_COOKIE", "WAF_NAME",
            "TIMEOUT", "DELAY_BETWEEN_REQUESTS", "ZAP_URL", "ZAP_API_KEY",
            "DVWA_USERNAME", "DVWA_PASSWORD"}

def environment(env_file=None):
    values = {}
    if env_file:
        for number, raw in enumerate(Path(env_file).read_text(encoding="utf-8-sig").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(f"Invalid settings line {number}.")
            key, value = line.split("=", 1)
            if key.strip() not in ENV_KEYS:
                raise ValueError(f"Unsupported settings key on line {number}.")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key.strip()] = value
    values.update({k: v for k, v in os.environ.items() if k in ENV_KEYS})
    return values

@dataclass(frozen=True)
class Config:
    target_url: str
    waf_name: str
    timeout: float
    delay_between_requests: float
    results_directory: Path
    log_directory: Path
    lab_reviewed: bool = False
    max_response_bytes: int = 1048576
    cookie: str = field(default="", repr=False)
    transport: str = "direct"
    zap_url: str = "http://127.0.0.1:8080"
    zap_api_key: str = field(default="", repr=False)
    auth_mode: str = "none"
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    auth_check_interval: int = 20
    scanner_ids: tuple = ()
    scan_timeout_seconds: int = 300
    scanner_lab_reviewed: bool = False

def load_config(path, env_file=None):
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    required = {"target_url", "waf_name", "timeout", "delay_between_requests",
                "results_directory", "log_directory"}
    allowed = required | {"lab_reviewed", "max_response_bytes", "transport", "zap_url",
                         "auth_mode", "auth_check_interval", "scanner_ids",
                         "scan_timeout_seconds", "scanner_lab_reviewed"}
    if not isinstance(data, dict) or required - data.keys():
        raise ValueError("Configuration is missing required fields.")
    if data.keys() - allowed:
        raise ValueError(f"Unknown configuration fields: {sorted(data.keys() - allowed)}")
    env = environment(env_file)
    waf = env.get("WAF_NAME", data["waf_name"])
    if waf not in {"unconfigured", "baseline", "modsecurity", "naxsi"}:
        raise ValueError("Invalid WAF name.")
    key = {"modsecurity": "MODSECURITY_URL", "naxsi": "NAXSI_URL"}.get(waf)
    url = validate_url(env.get(key, env.get("TARGET_URL", data["target_url"])))
    timeout = float(env.get("TIMEOUT", data["timeout"]))
    delay = float(env.get("DELAY_BETWEEN_REQUESTS", data["delay_between_requests"]))
    if not math.isfinite(timeout) or not 0 < timeout <= 120:
        raise ValueError("timeout must be finite and between 0 and 120 seconds.")
    if not math.isfinite(delay) or not 0.05 <= delay <= 60:
        raise ValueError("delay_between_requests must be between 0.05 and 60 seconds.")
    transport = data.get("transport", "zap")
    if transport not in {"zap", "direct"}:
        raise ValueError("transport must be zap or direct (explicit calibration only).")
    zap = validate_url(env.get("ZAP_URL", data.get("zap_url", "http://127.0.0.1:8080")))
    parts = urlsplit(zap)
    if parts.scheme != "http" or parts.hostname not in {"127.0.0.1", "localhost", "::1"} or parts.path:
        raise ValueError("ZAP API/proxy must be HTTP on Kali loopback with no path.")
    auth = data.get("auth_mode", "password")
    if auth not in {"password", "cookie", "none"}:
        raise ValueError("auth_mode must be password, cookie or none.")
    for flag in ("lab_reviewed", "scanner_lab_reviewed"):
        if type(data.get(flag, False)) is not bool:
            raise ValueError(f"{flag} must be a JSON boolean.")
    limit = data.get("max_response_bytes", 1048576)
    if type(limit) is not int or not 1024 <= limit <= 10485760:
        raise ValueError("Invalid response byte limit.")
    interval = data.get("auth_check_interval", 20)
    if type(interval) is not int or not 1 <= interval <= 100:
        raise ValueError("auth_check_interval must be 1..100.")
    scan_timeout = data.get("scan_timeout_seconds", 300)
    if type(scan_timeout) is not int or not 10 <= scan_timeout <= 1800:
        raise ValueError("scan_timeout_seconds must be 10..1800.")
    ids = data.get("scanner_ids", [])
    if not isinstance(ids, list) or any(not str(i).isdigit() for i in ids):
        raise ValueError("scanner_ids must be a list of numeric IDs reviewed on the installed ZAP.")
    def directory(key):
        value = data[key]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} must be a nonempty path.")
        p = Path(value)
        return (ROOT / p).resolve() if not p.is_absolute() else p.resolve()
    secret = {k: env.get(k, "") for k in ("LAB_COOKIE", "ZAP_API_KEY", "DVWA_USERNAME", "DVWA_PASSWORD")}
    if any("\r" in v or "\n" in v for v in secret.values()):
        raise ValueError("Credential settings must not contain line breaks.")
    return Config(url, waf, timeout, delay, directory("results_directory"), directory("log_directory"),
                  data.get("lab_reviewed", False), limit, secret["LAB_COOKIE"], transport, zap,
                  secret["ZAP_API_KEY"], auth, secret["DVWA_USERNAME"], secret["DVWA_PASSWORD"],
                  interval, tuple(map(str, ids)), scan_timeout, data.get("scanner_lab_reviewed", False))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, default=ROOT / "config/test_config.json")
    p.add_argument("--env-file", type=Path)
    args = p.parse_args()
    try:
        c = load_config(args.config, args.env_file)
        print(f"Valid: {c.waf_name}; target={c.target_url}; transport={c.transport}; auth={c.auth_mode}")
        print("Validation only: no requests sent.")
    except (OSError, ValueError, TypeError) as exc:
        p.exit(2, f"Configuration error: {exc}\n")

if __name__ == "__main__":
    main()
