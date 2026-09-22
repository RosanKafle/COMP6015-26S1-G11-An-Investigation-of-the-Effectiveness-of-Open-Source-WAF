"""Improve the inherited spider/active-scan pipeline with exact lab scope and exports."""
import argparse
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from config_loader import ROOT, load_config
from dvwa_session import DVWASession
from result_writer import write_json
from zap_client import ZapClient

def scope_regex(target):
    return re.escape(target.rstrip("/")) + r"/(?:index\.php|instructions\.php|vulnerabilities/(?:sqli|xss_r|exec|fi)/)(?:\?.*)?$"

def wait_scan(api, component, scan_id, timeout, session):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not session.check():
            raise ValueError("Authenticated session lost during scan; stop and repeat as a new run.")
        progress = int(api.call(component, "view", "status", scanId=scan_id)["status"])
        print(f"{component}: {progress}%", flush=True)
        if progress == 100:
            return
        time.sleep(2)
    raise ValueError("ZAP scan reached its configured time limit.")

def scrub_message(message):
    result = dict(message)
    for key in ("requestHeader", "responseHeader"):
        result[key] = "\n".join(line for line in message.get(key, "").splitlines()
                                if not line.lower().startswith(("cookie:", "set-cookie:", "authorization:")))
    return result

def scan(config, output):
    if config.transport != "zap" or not config.lab_reviewed or not config.scanner_lab_reviewed:
        raise ValueError("Verify lab, ZAP transport and scanner isolation/review before active scanning.")
    if not config.scanner_ids:
        raise ValueError("Select locally supported scanner_ids after reviewing scanner behaviour.")
    api = ZapClient(config)
    available = {str(s["id"]): s for s in api.call("ascan", "view", "scanners")["scanners"]}
    if set(config.scanner_ids) - available.keys():
        raise ValueError("A configured scanner ID is unavailable in this installed ZAP.")
    if api.call("context", "view", "contextList").get("contextList"):
        raise ValueError("Use a dedicated empty ZAP session for scanning; existing contexts are preserved.")
    if any(int(s.get("progress", 0)) < 100 for s in api.call("ascan", "view", "scans").get("scans", [])):
        raise ValueError("Another active scan is running.")
    session = DVWASession(config)
    name = "waf-" + uuid4().hex
    context = policy = None
    rules = []
    scan_ids = []
    output.mkdir(parents=True, exist_ok=False)
    finished = False
    try:
        session.login()
        write_json(output / "manifest.json", {
            "started_at": datetime.now(timezone.utc).isoformat(), "target": config.target_url,
            "waf": config.waf_name, "zap_version": api.version(),
            "scanner_ids": list(config.scanner_ids), "scope": scope_regex(config.target_url),
            "note": "Exploratory ZAP run, not the matched 600-case effectiveness experiment."})
        context = api.call("context", "action", "newContext", contextName=name)["contextId"]
        api.call("context", "action", "includeInContext", contextName=name, regex=scope_regex(config.target_url))
        api.call("context", "action", "setContextInScope", contextName=name, booleanInScope="true")
        api.call("core", "action", "setMode", mode="protect")
        # Header rules are URL-scoped and removed in finally; no global cookie setting.
        cookie = "; ".join(f"{c.name}={c.value}" for c in session.session.cookies)
        for header, value in (("Cookie", cookie), ("User-Agent", session.session.headers["User-Agent"])):
            description = name + "-" + header
            api.call("replacer", "action", "addRule", description=description, enabled="true",
                     matchType="REQ_HEADER", matchRegex="false", matchString=header,
                     replacement=value, url=scope_regex(config.target_url))
            rules.append(description)
        api.call("ascan", "action", "addScanPolicy", scanPolicyName=name)
        policy = name
        api.call("ascan", "action", "disableAllScanners", scanPolicyName=name)
        api.call("ascan", "action", "enableScanners", ids=",".join(config.scanner_ids), scanPolicyName=name)
        api.call("ascan", "action", "setOptionThreadPerHost", Integer="1")
        api.call("ascan", "action", "setOptionDelayInMs", Integer=str(int(config.delay_between_requests * 1000)))
        api.call("spider", "action", "setOptionProcessForm", Boolean="false")
        api.call("spider", "action", "setOptionPostForm", Boolean="false")
        sid = api.call("spider", "action", "scan", url=config.target_url + "/index.php",
                       contextName=name, subtreeOnly="true", maxChildren="10", recurse="true")["scan"]
        scan_ids.append(("spider", sid))
        wait_scan(api, "spider", sid, config.scan_timeout_seconds, session)
        # Seed the same four DVWA parameter routes from the inherited pipeline.
        seeds = [("/vulnerabilities/sqli/", "GET", "id=1&Submit=Submit"),
                 ("/vulnerabilities/xss_r/", "GET", "name=WAF_LAB_NORMAL"),
                 ("/vulnerabilities/exec/", "POST", "ip=127.0.0.1&Submit=Submit"),
                 ("/vulnerabilities/fi/", "GET", "page=file1.php")]
        message_ids = set()
        alert_ids = set()
        for endpoint, method, data in seeds:
            session.request(endpoint, method, data)
            url = config.target_url + endpoint + ("?" + data if method == "GET" else "")
            sid = api.call("ascan", "action", "scan", url=url, recurse="false",
                           inScopeOnly="true", contextId=context, scanPolicyName=name,
                           method=method, postData=data if method == "POST" else "")["scan"]
            scan_ids.append(("ascan", sid))
            wait_scan(api, "ascan", sid, config.scan_timeout_seconds, session)
            message_ids.update(map(str, api.call("ascan", "view", "messagesIds", scanId=sid)["messagesIds"]))
            alert_ids.update(map(str, api.call("ascan", "view", "alertsIds", scanId=sid)["alertsIds"]))
        # Separate scan-owned messages from login/polling traffic and old sessions.
        for mid in sorted(message_ids):
            message = api.call("core", "view", "message", id=mid)["message"]
            write_json(output / f"message-{mid}.json", scrub_message(message))
        for aid in sorted(alert_ids):
            write_json(output / f"alert-{aid}.json", api.call("alert", "view", "alert", id=aid))
        write_json(output / "scan_index.json", {"message_ids": sorted(message_ids), "alert_ids": sorted(alert_ids)})
        finished = True
    finally:
        cleanup_errors = []
        for component, sid in scan_ids:
            try:
                api.call(component, "action", "stop", scanId=sid)
            except Exception:
                cleanup_errors.append(component + " stop failed; inspect ZAP")
        for description in rules:
            try:
                api.call("replacer", "action", "removeRule", description=description)
            except Exception:
                cleanup_errors.append("Replacer removal failed; close this dedicated ZAP session")
        if policy:
            try:
                api.call("ascan", "action", "removeScanPolicy", scanPolicyName=policy)
            except Exception:
                cleanup_errors.append("Policy cleanup failed")
        if context:
            try:
                api.call("context", "action", "removeContext", contextName=name)
            except Exception:
                cleanup_errors.append("Context cleanup failed")
        session.close()
        write_json(output / "completion.json", {"completed": finished, "cleanup_errors": cleanup_errors})
        for error in cleanup_errors:
            print(error)
    print(f"ZAP exports: {output}; alerts/statuses are not WAF classifications.")

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, default=ROOT / "config/test_config.json")
    p.add_argument("--env-file", type=Path)
    p.add_argument("--list-scanners", action="store_true", help="Read the installed ZAP scanner inventory.")
    p.add_argument("--execute", action="store_true")
    a = p.parse_args()
    try:
        c = load_config(a.config, a.env_file)
        if a.list_scanners:
            print(json.dumps(ZapClient(c).call("ascan", "view", "scanners"), indent=2))
        elif a.execute:
            scan(c, c.results_directory / ("zap_" + uuid4().hex))
        else:
            print(f"PLAN ONLY: target={c.target_url}; configured scanners={c.scanner_ids}")
    except ValueError as exc:
        p.exit(2, f"ZAP validation error: {exc}\n")
    except Exception as exc:
        # Network exception messages can include sensitive query strings; do not print them.
        p.exit(2, f"ZAP operation failed ({type(exc).__name__}). Check configuration, credentials and private ZAP logs.\n")

if __name__ == "__main__":
    main()
