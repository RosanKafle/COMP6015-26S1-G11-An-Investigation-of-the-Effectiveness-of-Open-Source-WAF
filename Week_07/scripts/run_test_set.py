"""Plan by default; use --execute only after reviewing the configured local lab."""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
import logging
import random
from pathlib import Path
import time
from uuid import uuid4
from config_loader import ROOT, load_config
from request_runner import execute
from dvwa_session import DVWASession
from zap_client import ZapClient
from result_writer import ResultWriter, sha256, write_json
from test_loader import CATEGORIES, load_tests

def parser_for(description: str = __doc__) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--config", type=Path, default=ROOT / "config/test_config.json")
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--category", choices=(*CATEGORIES, "all"), default="normal")
    parser.add_argument("--test-directory", type=Path, default=ROOT / "test_cases")
    parser.add_argument("--include-variants", action="store_true")
    parser.add_argument("--expect-test-set-sha256", help="Require the digest from the first WAF run.")
    parser.add_argument("--execute", action="store_true", help="Send real lab requests; default only prints a plan.")
    parser.add_argument("--exclude-normal", action="store_true")
    parser.add_argument("--limit", type=int, help="Pilot prefix only; use the same selection for both WAFs.")
    return parser

def run(args: argparse.Namespace) -> Path | None:
    config = load_config(args.config, args.env_file)
    cases = [c for c in load_tests(args.test_directory, args.include_variants)
             if args.category == "all" or c.category == args.category]
    if getattr(args, "exclude_normal", False):
        cases = [c for c in cases if c.category != "normal"]
    random.Random(2026).shuffle(cases)
    if getattr(args, "limit", None) is not None:
        if not 1 <= args.limit <= len(cases):
            raise ValueError("limit must be between 1 and selected case count.")
        cases = cases[:args.limit]
    if not cases:
        raise ValueError("No cases matched the selected category.")
    serialised = json.dumps([asdict(c) for c in cases], sort_keys=True, ensure_ascii=False).encode("utf-8")
    digest = sha256(serialised)
    if args.expect_test_set_sha256 and args.expect_test_set_sha256 != digest:
        raise ValueError("Selected corpus differs from the required test-set SHA-256.")
    skipped = sum(c.payload.startswith("PLACEHOLDER") or c.review_status == "REQUIRES_REVIEW" for c in cases)
    print(f"WAF={config.waf_name}; target={config.target_url}; selected={len(cases)}; skipped={skipped}")
    print(f"Test-set SHA-256: {digest}")
    if not args.execute:
        print("PLAN ONLY: no requests sent and no experimental results created.")
        return None
    if not config.lab_reviewed or config.waf_name == "unconfigured":
        raise ValueError("Set the WAF name and lab_reviewed=true after verifying lab prerequisites.")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid4().hex[:12]
    run_dir = config.results_directory / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    write_json(run_dir / "test_set.json", [asdict(c) for c in cases])
    safe_config = asdict(config)
    for secret in ("cookie", "zap_api_key", "username", "password"):
        safe_config.pop(secret)
    safe_config = {k: str(v) if isinstance(v, Path) else v for k, v in safe_config.items()}
    manifest = {"run_id": run_id, "started_at": datetime.now(timezone.utc).isoformat(),
                "test_set_sha256": digest, "config": safe_config,
                "cookie_supplied": bool(config.cookie), "selected_cases": len(cases), "order_seed": 2026}
    write_json(run_dir / "manifest.json", manifest)
    result = run_dir / "results.csv"
    writer = ResultWriter(result)
    counts = {"SENT": 0, "ERROR": 0, "SKIPPED": 0}
    completed = False
    session = None
    try:
        if config.transport == "zap":
            if config.auth_mode == "none":
                raise ValueError("ZAP/DVWA experiments require authenticated sessions.")
            write_json(run_dir / "zap_version.json", {"version": ZapClient(config).version()})
        if config.auth_mode != "none":
            session = DVWASession(config)
            session.login()
        for index, case in enumerate(cases):
            if session and index % config.auth_check_interval == 0:
                session.ensure_authenticated()
            row = execute(case, config, run_id, digest, run_dir, session)
            writer.write(row)
            counts[row["execution_status"]] += 1
            logging.info("%s %s HTTP=%s action=UNKNOWN", case.test_id, row["execution_status"], row["http_status"])
            time.sleep(config.delay_between_requests)
        completed = True
    finally:
        writer.close()
        if session:
            session.close()
        write_json(run_dir / "completion.json", {
            "completed": completed, "finished_at": datetime.now(timezone.utc).isoformat(),
            "counts": counts, "session_logins": session.renewals if session else 0, "results_sha256": sha256(result.read_bytes())
        })
    print(f"Collected: {result}")
    print("Every disposition remains UNKNOWN pending evidence review.")
    return result

def main() -> None:
    parser = parser_for()
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        run(args)
    except (ValueError, OSError, TypeError) as exc:
        parser.exit(2, f"Run failed: {exc}\n")

if __name__ == "__main__":
    main()
