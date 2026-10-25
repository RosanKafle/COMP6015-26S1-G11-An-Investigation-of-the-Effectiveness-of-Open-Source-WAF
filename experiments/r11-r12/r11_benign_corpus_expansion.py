#!/usr/bin/env python3
"""
Benign/false-positive corpus expansion: 4 new controls filling a real gap
in the existing 4 (which only covered SQLi/XSS-shaped benign text) --
these target command-injection-shaped and path-traversal-shaped benign
prose, since CMD injection is the paper's central finding (R11-CMD-E03 /
R12 newline miss) yet had zero benign coverage of its own character set.

Machine: KALI. All 4 route through the same safe reflected-XSS sink
(vulnerabilities/xss_r/index.php?name=...) the existing 4 benign controls
use -- display-only, never executed as a shell command or file path, so
there is no risk to the DVWA host regardless of WAF outcome, even though
the text contains ';', '|', '&&', '../' characters.

Usage:
  DVWA_PASSWORD=... python3 r11_benign_corpus_expansion.py \
      --out evidence/r11-benign-expansion-$(date -u +%Y%m%dT%H%M%SZ)
"""
import argparse, json, os, sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests

sys.path.insert(0, str(Path(__file__).parent))
from legacy_v10 import login, BASE_URLS

CASES = [
    ("R11-BEN-CMD01", "Chain steps with a semicolon; then pipe output | to a log"),
    ("R11-BEN-CMD02", "Both success && failure paths are logged for audit"),
    ("R11-BEN-PTH01", "Store nightly backups under ../archive/2026 per our folder convention"),
    ("R11-BEN-SQL02", "Please select your preferred delivery date from the list below"),
]

def utc_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--username', default=os.environ.get('DVWA_USERNAME', 'admin'))
    ap.add_argument('--reps', type=int, default=3)
    args = ap.parse_args()
    password = os.environ.get('DVWA_PASSWORD')
    if not password:
        sys.exit('DVWA_PASSWORD is required in the environment; it is never written to evidence.')

    out_dir = Path(args.out)
    if out_dir.exists() and any(out_dir.iterdir()):
        sys.exit(f'Refusing to write into existing non-empty directory: {out_dir}')
    out_dir.mkdir(parents=True, exist_ok=True)

    run_id = out_dir.name
    manifest = []

    # --- Baseline sanity phase: confirm each case is genuinely benign ---
    # (reflects cleanly, HTTP 200, text present in body -- not itself blocked
    # or erroring before we ever compare WAFs against each other)
    base_url = BASE_URLS['baseline']
    session = requests.Session()
    auth = login(session, base_url, args.username, password)
    print(f"[benign-expansion] baseline auth: passed={auth.get('passed')}")

    baseline_ok = True
    for case_id, text in CASES:
        url = f"{base_url}/DVWA/vulnerabilities/xss_r/index.php?name={quote(text)}"
        r = session.get(url, headers={'X-WAF-Test-ID': case_id, 'X-WAF-Run-ID': run_id, 'X-WAF-Repetition': '0'}, timeout=15)
        reflected = text in r.text
        print(f"[baseline] {case_id}: http={r.status_code} reflected={reflected}")
        manifest.append({
            'phase': 'baseline', 'case_id': case_id, 'env': 'baseline', 'repetition': 0,
            'url': url, 'http_status': r.status_code, 'reflected': reflected,
            'timestamp_utc': utc_now(),
        })
        (out_dir / f"baseline.{case_id}.body.html").write_text(r.text)
        if r.status_code != 200 or not reflected:
            baseline_ok = False

    if not baseline_ok:
        print("[benign-expansion] WARNING: one or more cases did not reflect cleanly at "
              "baseline -- review before treating protected-phase results as meaningful.")

    # --- Protected phase: all 3 WAFs, 3 reps each ---
    for env in ('modsec', 'coraza', 'naxsi'):
        env_url = BASE_URLS[env]
        env_session = requests.Session()
        env_auth = login(env_session, env_url, args.username, password)
        print(f"[benign-expansion] {env} auth: passed={env_auth.get('passed')}")
        for case_id, text in CASES:
            for rep in range(1, args.reps + 1):
                url = f"{env_url}/DVWA/vulnerabilities/xss_r/index.php?name={quote(text)}"
                try:
                    r = env_session.get(url, headers={
                        'X-WAF-Test-ID': case_id, 'X-WAF-Run-ID': run_id, 'X-WAF-Repetition': str(rep),
                    }, timeout=15)
                    status = r.status_code
                    blocked = status in (403, 406) or status >= 500
                    body_snippet = r.text[:200]
                    error = None
                except Exception as e:
                    status = None
                    blocked = None
                    body_snippet = None
                    error = str(e)
                rec = {
                    'phase': 'protected', 'case_id': case_id, 'env': env, 'repetition': rep,
                    'url': url, 'http_status': status, 'blocked': blocked,
                    'body_snippet': body_snippet, 'error': error, 'timestamp_utc': utc_now(),
                }
                manifest.append(rec)
                print(f"[protected] {env} {case_id} rep{rep}: http={status} blocked={blocked}")
                if status is not None:
                    (out_dir / f"{env}.{case_id}.rep{rep}.body.html").write_text(r.text)

    with open(out_dir / 'benign_expansion_manifest.jsonl', 'w') as f:
        for rec in manifest:
            f.write(json.dumps(rec) + '\n')

    protected = [m for m in manifest if m['phase'] == 'protected']
    by_env = {}
    for env in ('modsec', 'coraza', 'naxsi'):
        env_recs = [m for m in protected if m['env'] == env]
        blocked_count = sum(1 for m in env_recs if m['blocked'])
        by_env[env] = {'total': len(env_recs), 'blocked': blocked_count, 'passed': len(env_recs) - blocked_count}

    summary = {
        'generated_utc': utc_now(),
        'run_id': run_id,
        'baseline_ok': baseline_ok,
        'cases': [c[0] for c in CASES],
        'by_env': by_env,
    }
    with open(out_dir / 'summary.json', 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\n[benign-expansion] baseline_ok={baseline_ok}")
    for env, s in by_env.items():
        print(f"[benign-expansion] {env}: {s['blocked']}/{s['total']} false-positive-blocked")
    print(f"[benign-expansion] wrote: {out_dir / 'benign_expansion_manifest.jsonl'}")

if __name__ == '__main__':
    main()
