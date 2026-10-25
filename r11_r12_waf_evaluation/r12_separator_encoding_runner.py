#!/usr/bin/env python3
"""
R12 controlled separator/encoding follow-up runner v2 (corrected, authenticated).
Machine: KALI ONLY. Run from the corrected runner directory, same folder as
legacy_v10.py (imported directly below).
"""
import argparse
import getpass
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

try:
    import requests
except ImportError:
    sys.exit(
        "requests not found. Use the project runtime interpreter, e.g.:\n"
        "  /home/sadaiba/COMP6016_S2_2026/week6-runtime.d5AqGB/bin/python "
        + " ".join(sys.argv)
    )

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from legacy_v10 import login, set_security_low, BASE_URLS
except ImportError:
    sys.exit(
        "Could not import legacy_v10.py. This script must sit in the same "
        "directory as legacy_v10.py (the corrected runner directory), because "
        "it reuses that file's proven login()/set_security_low() logic rather "
        "than reimplementing DVWA authentication."
    )

BASELINE_BASE = BASE_URLS["baseline"]
WAF_BASES = {k: v for k, v in BASE_URLS.items() if k != "baseline"}
EXEC_PATH = "/DVWA/vulnerabilities/exec/index.php"

SEPARATORS = {"SEMI": ";", "NL": "\n", "AND": "&&", "PIPE": "|"}
SPACE_ENCODINGS = {"PCT": "%20", "PLUS": "+"}


def get_dvwa_password() -> str:
    env_pw = os.environ.get("DVWA_PASSWORD")
    if env_pw:
        return env_pw
    try:
        return getpass.getpass("DVWA admin password: ")
    except Exception:
        sys.exit("Could not read password. Set DVWA_PASSWORD env var instead, e.g.:\n"
                  "  printf 'DVWA password: '; IFS= read -r -s DVWA_PASSWORD; export DVWA_PASSWORD")


def build_logical_and_transport(sep_key, space_key, canary):
    sep = SEPARATORS[sep_key]
    if sep_key in ("AND", "PIPE"):
        logical = f"127.0.0.1 {sep} printf {canary}"
    else:
        logical = f"127.0.0.1{sep}printf {canary}"
    encoded = quote(logical, safe="")
    if space_key == "PLUS":
        encoded = encoded.replace("%20", "+")
    return logical, encoded


def make_cases(run_id):
    cases = []
    for sep_key in SEPARATORS:
        for space_key in SPACE_ENCODINGS:
            case_id = f"R12-CMD-{sep_key}-{space_key}"
            canary = f"R12{sep_key}{space_key}{run_id[-6:]}"
            logical, transport = build_logical_and_transport(sep_key, space_key, canary)
            cases.append({
                "case_id": case_id, "role": "attack", "category": "command_injection",
                "separator": sep_key, "space_encoding": space_key, "canary": canary,
                "logical_payload": logical, "body": f"ip={transport}&Submit=Submit",
            })
    cases.append({
        "case_id": "R12-BEN-IP01", "role": "control", "category": "benign",
        "separator": None, "space_encoding": None, "canary": None,
        "logical_payload": "127.0.0.1", "body": "ip=127.0.0.1&Submit=Submit",
    })
    neg_canary = f"R12NEGDBL{run_id[-6:]}"
    neg_logical = f"127.0.0.1;printf {neg_canary}"
    neg_transport = quote(quote(neg_logical, safe=""), safe="")
    cases.append({
        "case_id": "R12-CMD-NEG-DBLENC", "role": "attack_candidate_unvalidated",
        "category": "command_injection", "separator": "SEMI", "space_encoding": "DOUBLE",
        "canary": neg_canary, "logical_payload": neg_logical,
        "body": f"ip={neg_transport}&Submit=Submit",
    })
    return cases


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def canary_in_output(body_text, canary):
    if canary is None:
        return True
    idx = body_text.find("<pre")
    if idx == -1:
        return False
    end = body_text.find("</pre>", idx)
    block = body_text[idx: end + len("</pre>")] if end != -1 else body_text[idx:]
    return canary in block


def authenticated_session(base_url, password):
    session = requests.Session()
    session.trust_env = False
    auth = login(session, base_url, "admin", password)
    if not auth.get("passed"):
        sys.exit(f"[R12] authentication/security-low gate failed against {base_url}: {auth}")
    return session, auth


def send(session, url, body, headers, timeout=15):
    return session.post(
        url, data=body.encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded", **headers},
        timeout=timeout, allow_redirects=False,
    )


def corr_headers(run_id, case_id, rep, waf=None):
    h = {
        "X-WAF-Run-ID": run_id, "X-WAF-Test-ID": case_id, "X-WAF-Repetition": str(rep),
        "X-R12-Run": run_id, "X-R12-Case": case_id, "X-R12-Rep": str(rep),
    }
    if waf:
        h["X-R12-WAF"] = waf
    return h


def run_baseline(out_dir, run_id, password):
    session, auth = authenticated_session(BASELINE_BASE, password)
    cases = make_cases(run_id)
    manifest, gate_report = [], []
    for case in cases:
        passed_reps = []
        for rep in range(1, 4):
            headers = corr_headers(run_id, case["case_id"], rep)
            resp = send(session, f"{BASELINE_BASE}{EXEC_PATH}", case["body"], headers)
            body_text = resp.text
            ok = canary_in_output(body_text, case["canary"])
            passed_reps.append(ok)
            with open(os.path.join(out_dir, f"{case['case_id']}.rep{rep}.body.html"), "w", encoding="utf-8") as f:
                f.write(body_text)
            manifest.append({
                "run_id": run_id, "case_id": case["case_id"], "repetition": rep, "phase": "baseline",
                "role": case["role"], "category": case["category"], "separator": case["separator"],
                "space_encoding": case["space_encoding"], "canary": case["canary"],
                "logical_payload": case["logical_payload"], "transport_body": case["body"],
                "http_status": resp.status_code, "body_sha256": sha256_bytes(resp.content),
                "canary_in_output_block": ok, "started_utc": datetime.now(timezone.utc).isoformat(),
            })
        gate_report.append({
            "case_id": case["case_id"], "role": case["role"],
            "baseline_pass_all_3": all(passed_reps), "baseline_pass_reps": passed_reps,
        })
    with open(os.path.join(out_dir, "run_manifest.jsonl"), "w") as f:
        for rec in manifest:
            f.write(json.dumps(rec) + "\n")
    with open(os.path.join(out_dir, "baseline_gate_report.json"), "w") as f:
        json.dump(gate_report, f, indent=2)
    with open(os.path.join(out_dir, "run_metadata.json"), "w") as f:
        json.dump({
            "run_id": run_id, "phase": "baseline", "runner_version": "v2-authenticated",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "authentication": {k: v for k, v in auth.items() if k != "security"},
            "n_cases": len(cases), "n_observations": len(manifest),
        }, f, indent=2)
    print(f"[R12] baseline complete: {len(cases)} cases x3 reps = {len(manifest)} observations")
    print(f"[R12] gate report: {os.path.join(out_dir, 'baseline_gate_report.json')}")
    failed = [g["case_id"] for g in gate_report if not g["baseline_pass_all_3"]]
    passed = [g["case_id"] for g in gate_report if g["baseline_pass_all_3"]]
    print(f"[R12] PASSED ({len(passed)}): {passed}")
    if failed:
        print(f"[R12] EXCLUDED ({len(failed)}, do not send to WAFs): {failed}")


def run_protected(out_dir, run_id, gated_case_ids, password):
    all_cases = {c["case_id"]: c for c in make_cases(run_id)}
    cases = [all_cases[cid] for cid in gated_case_ids if cid in all_cases]
    if not cases:
        sys.exit("[R12] no valid gated case_ids supplied; aborting protected phase")
    manifest = []
    for waf_name, base_url in WAF_BASES.items():
        session, _auth = authenticated_session(base_url, password)
        for case in cases:
            for rep in range(1, 4):
                headers = corr_headers(run_id, case["case_id"], rep, waf=waf_name)
                resp = send(session, f"{base_url}{EXEC_PATH}", case["body"], headers)
                body_text = resp.text
                ok = canary_in_output(body_text, case["canary"]) if resp.status_code == 200 else None
                with open(os.path.join(out_dir, f"{waf_name}.{case['case_id']}.rep{rep}.body.html"), "w", encoding="utf-8") as f:
                    f.write(body_text)
                manifest.append({
                    "run_id": run_id, "waf": waf_name, "case_id": case["case_id"], "repetition": rep,
                    "phase": "protected", "role": case["role"], "category": case["category"],
                    "separator": case["separator"], "space_encoding": case["space_encoding"],
                    "canary": case["canary"], "http_status": resp.status_code,
                    "body_sha256": sha256_bytes(resp.content), "command_effect_observed": ok,
                    "started_utc": datetime.now(timezone.utc).isoformat(),
                })
    with open(os.path.join(out_dir, "protected_manifest.jsonl"), "w") as f:
        for rec in manifest:
            f.write(json.dumps(rec) + "\n")
    print(f"[R12] protected run complete: {len(cases)} cases x {len(WAF_BASES)} WAFs x 3 reps = {len(manifest)} observations")
    print("[R12] NEXT: pull server logs (UBUNTU) for the same run_id/case_id/rep headers before drawing conclusions.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", choices=["baseline", "protected"], required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--gated-cases")
    args = ap.parse_args()
    password = get_dvwa_password()

    if args.phase == "baseline":
        if os.path.exists(args.out_dir) and os.listdir(args.out_dir):
            sys.exit(f"[R12] refusing to run: {args.out_dir} already exists and is non-empty. Use a fresh directory.")
        os.makedirs(args.out_dir, exist_ok=True)
        run_id = f"r12-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
        run_baseline(args.out_dir, run_id, password)
    else:
        if not args.gated_cases:
            sys.exit("[R12] --phase protected requires --gated-cases <file>")
        if not os.path.isdir(args.out_dir):
            sys.exit(f"[R12] {args.out_dir} does not exist; run --phase baseline first into this directory")
        with open(args.gated_cases) as f:
            gated = [line.strip() for line in f if line.strip()]
        meta_path = os.path.join(args.out_dir, "run_metadata.json")
        run_id = None
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                run_id = json.load(f).get("run_id")
        if not run_id:
            run_id = f"r12-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
        run_protected(args.out_dir, run_id, gated, password)


if __name__ == "__main__":
    main()
