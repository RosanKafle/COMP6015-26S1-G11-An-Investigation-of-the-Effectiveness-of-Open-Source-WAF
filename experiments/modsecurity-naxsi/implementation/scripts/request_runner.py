"""Execute one reviewed test; HTTP status alone never sets the WAF action."""
from dataclasses import asdict
from datetime import datetime, timezone
import json
import time
import requests
from pathlib import Path
from urllib.parse import quote, urlencode
from uuid import uuid4
from config_loader import Config
from lab_http import NETWORK_ERRORS, request
from result_writer import sha256, write_json
from test_loader import TestCase

def case_digest(case: TestCase) -> str:
    return sha256(json.dumps(asdict(case), sort_keys=True, ensure_ascii=False).encode("utf-8"))

def encode_fields(case: TestCase) -> str:
    """Preencoded variants bypass exactly one form-encoding step, deliberately."""
    value = case.payload if case.wire_encoding == "preencoded" else quote(case.payload, safe="")
    encoded = quote(case.parameter, safe="") + "=" + value if case.parameter else ""
    if case.category in ("sqli", "command_injection"):
        encoded += "&" + urlencode({"Submit": "Submit"})
    return encoded

def execute(case: TestCase, config: Config, run_id: str,
            digest: str, run_dir: Path, client=None) -> dict:
    request_id = uuid4().hex
    row = {k: v for k, v in asdict(case).items() if k != "description"}
    row.update(run_id=run_id, timestamp=datetime.now(timezone.utc).isoformat(),
               waf=config.waf_name, http_status="", response_length="", waf_action="UNKNOWN",
               classification="UNKNOWN", notes="", request_id=request_id,
               test_set_sha256=digest, case_sha256=case_digest(case), response_file="",
               response_sha256="", request_file="", execution_status="SKIPPED",
               evidence_reference="", response_time_seconds="")
    if case.payload.startswith("PLACEHOLDER"):
        row["notes"] = "PLACEHOLDER test: not sent; local fixture and payload review required."
        return row
    if case.review_status == "REQUIRES_REVIEW":
        row["notes"] = "Variant not sent: semantic and wire-encoding review required."
        return row
    encoded = encode_fields(case)
    headers = {"X-Lab-Request-ID": request_id, "Accept-Encoding": "identity"}
    if config.cookie and client is None:
        headers["Cookie"] = config.cookie
    body = None
    query = ""
    if case.method == "POST":
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = encoded.encode("ascii")
    else:
        query = encoded
    request_path = run_dir / f"{case.test_id}.request.json"
    write_json(request_path, {
        "request_id": request_id, "base_url": config.target_url, "endpoint": case.endpoint,
        "method": case.method, "encoded_fields": encoded,
        "cookie_supplied": bool(config.cookie), "timestamp": row["timestamp"],
        "note": "Cookie omitted intentionally; body/query retained as sent."
    })
    row["request_file"] = request_path.name
    row["execution_status"] = "ERROR"
    started = time.perf_counter()
    try:
        response = request(config.target_url, case.endpoint, case.method, query, body,
                           headers, config.timeout, config.max_response_bytes) if client is None else client.request(case.endpoint, case.method, encoded, headers)
        elapsed = round(time.perf_counter() - started, 6)
        response_path = run_dir / f"{case.test_id}.response.bin"
        with response_path.open("xb") as handle:
            handle.write(response.body)
        row.update(response_time_seconds=elapsed, http_status=response.status, response_length=len(response.body),
                   response_file=response_path.name, response_sha256=sha256(response.body),
                   execution_status="SENT",
                   notes="HTTP observed; WAF/backend evidence required for disposition.")
        if response.truncated:
            row["notes"] += " Response truncated at configured byte limit; length is captured bytes."
        if 300 <= response.status < 400:
            row["notes"] += " Redirect not followed; verify session and intended endpoint."
    except (*NETWORK_ERRORS, requests.RequestException) as exc:
        row["response_time_seconds"] = round(time.perf_counter() - started, 6)
        row["notes"] = f"Request failed ({type(exc).__name__}); no WAF disposition inferred."
    return row
