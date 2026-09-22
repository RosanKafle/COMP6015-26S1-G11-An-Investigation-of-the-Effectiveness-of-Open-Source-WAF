#!/usr/bin/env python3
"""Matched local-lab collection; default is offline validation only."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import getpass
import hashlib
import json
from pathlib import Path
import re
import uuid
import requests
import run_corrected as core

ROOT = Path(__file__).resolve().parent
EXCLUDED = {'R11-SQLI-E03', 'R11-XSS-E04', 'R11-PTH-E03'}
ENVIRONMENTS = {'modsec': 'http://waf-lab.local',
                'coraza': 'http://waf-lab.local:8080',
                'naxsi': 'http://waf-lab.local:8084'}
CATALOGUE_HASH = 'ed557ae6df5ce8c7028bb68ba634af7b80ce26825779f061296983b2c12b0211'
CORE_HASH = '830974d3ff2dc10b58f4b668e48a8dcb6dc758090f8f3a94aca792a3a94a0c38'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def validate(baseline, browser):
    if sha(ROOT / 'catalogue.json') != CATALOGUE_HASH or sha(ROOT / 'run_corrected.py') != CORE_HASH:
        raise ValueError('Reviewed catalogue/runner changed; stop for review')
    cases = json.loads((ROOT / 'catalogue.json').read_text())
    core.check(cases)
    meta = json.loads((baseline / 'run_metadata.json').read_text())
    if meta['run_id'] != 'r11-baseline-20260921T072551Z-8696e008':
        raise ValueError('Unexpected baseline run')
    if meta['catalogue_sha256'] != CATALOGUE_HASH or not meta['authentication']['passed']:
        raise ValueError('Baseline configuration/authentication mismatch')
    rows = [json.loads(line) for line in (baseline / 'results.jsonl').read_text().splitlines()]
    if len(rows) != 28 or len({r['case_id'] for r in rows}) != 28:
        raise ValueError('Expected 28 unique baseline observations')
    by_id = {r['case_id']: r for r in rows}
    for c in cases:
        r = by_id[c['case_id']]
        stem = baseline / c['case_id']
        if sha(Path(str(stem) + '.body.html')) != r['response_sha256']:
            raise ValueError('Baseline response hash mismatch')
        if sha(Path(str(stem) + '.request.json')) != r['request_sha256']:
            raise ValueError('Baseline request hash mismatch')
    checks = json.loads(browser.read_text())
    if len(checks) != 8 or len({r['case_id'] for r in checks}) != 8:
        raise ValueError('Expected eight unique browser results')
    checked = {r['case_id']: r for r in checks}
    for c in cases:
        if c['category'] != 'reflected_xss':
            continue
        b = checked[c['case_id']]
        if b['source_sha256'] != by_id[c['case_id']]['response_sha256']:
            raise ValueError('Browser/source hash mismatch')
        if c['case_id'] not in EXCLUDED:
            if b.get('error') or not b['offline_execution_confirmed'] or c['marker'] not in b['dialogs']:
                raise ValueError('Browser execution not confirmed: ' + c['case_id'])
    selected = [c for c in cases if c['case_id'] not in EXCLUDED]
    assert len(selected) == 25
    return selected

def collect(cases, baseline, browser):
    password = getpass.getpass('DVWA password: ')
    if not password:
        raise ValueError('Empty password; nothing sent')
    run_id = 'r11-protected-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    out = ROOT / 'evidence' / run_id
    out.mkdir(parents=True, exist_ok=False)
    meta = {'run_id': run_id, 'started_utc': datetime.now(timezone.utc).isoformat(),
            'catalogue_sha256': CATALOGUE_HASH, 'runner_sha256': sha(Path(__file__)),
            'core_sha256': sha(ROOT / 'run_corrected.py'),
            'login_helper_sha256': sha(ROOT / 'legacy_v10.py'),
            'baseline_directory': str(baseline), 'browser_results_sha256': sha(browser),
            'environments': ENVIRONMENTS, 'authentication': {}, 'repetitions': 3,
            'attack_cases': 21, 'control_cases': 4, 'planned_observations': 225,
            'excluded_no_baseline_effect': sorted(EXCLUDED),
            'xml': 'NOT_EXECUTED', 'classification': 'PENDING_SERVER_LOG_CORRELATION',
            'xss_validation': 'offline replay; live-origin execution not established',
            'observations': 0, 'requests_attempted': 0, 'collection_status': 'INCOMPLETE'}
    (out / 'catalogue.json').write_bytes((ROOT / 'catalogue.json').read_bytes())
    (out / 'browser_results.json').write_bytes(browser.read_bytes())
    counts = Counter()
    print('Evidence_directory=' + str(out), flush=True)
    try:
        for env, base in ENVIRONMENTS.items():
            with requests.Session() as session:
                session.trust_env = False
                auth = core.login(session, base, 'admin', password)
                auth.get('security', {}).pop('cookie_header_for_prepared_probe', None)
                meta['authentication'][env] = auth
                if not auth.get('passed'):
                    raise RuntimeError(env + ': authentication/security gate failed')
                print(env + ' Authentication=PASS', flush=True)
                core.BASE = base
                for rep in range(1, 4):
                    for c in cases:
                        stem = f"{c['case_id']}__{env}__r{rep}"
                        req, wire = core.prepare(session, c, run_id, rep)
                        control = c['case_id'].startswith('R11-BEN-')
                        row = {'run_id': run_id, 'case_id': c['case_id'], 'environment': env,
                               'repetition': rep, 'role': 'control' if control else 'attack',
                               'category': c['category'], 'encoding': c['encoding'],
                               'started_utc': datetime.now(timezone.utc).isoformat(),
                               'request_file': stem + '.request.json', 'body_file': stem + '.body.html',
                               'classification': 'PENDING_SERVER_LOG_CORRELATION'}
                        request_path = out / row['request_file']
                        request_path.write_text(json.dumps({'method': req.method, 'url': req.url,
                            'headers': core.safe_headers(req.headers), 'body': req.body,
                            'intended_encoded_parameter_string': wire}, indent=2))
                        row['request_sha256'] = sha(request_path)
                        try:
                            meta['requests_attempted'] += 1
                            response = session.send(req, timeout=20, allow_redirects=False)
                            (out / row['body_file']).write_bytes(response.content)
                            row.update(http_status=response.status_code,
                                response_sha256=hashlib.sha256(response.content).hexdigest(),
                                response_headers=core.safe_headers(response.headers),
                                elapsed_seconds=response.elapsed.total_seconds(),
                                final_url=response.url,
                                marker_present=bool(c.get('marker') and c['marker'] in response.text),
                                sql_record_labels=len(re.findall('First name:', response.text, re.I)))
                            row['preliminary_outcome'] = ('blocked_candidate' if response.status_code == 403
                                else 'allowed_candidate' if response.status_code == 200 else 'indeterminate')
                            if response.is_redirect or re.search(r'name=[\"\']password[\"\']', response.text, re.I):
                                raise RuntimeError('Redirect/login response; stopping')
                            counts[(env, row['role'], response.status_code)] += 1
                            if not control and response.status_code != 403:
                                print(f"REVIEW {stem} HTTP={response.status_code} marker={row['marker_present']}", flush=True)
                        except Exception as exc:
                            row['error'] = type(exc).__name__
                            row['preliminary_outcome'] = 'indeterminate'
                            raise
                        finally:
                            with (out / 'results.jsonl').open('a') as f:
                                f.write(json.dumps(row) + '\n')
                            meta['observations'] += 1
                    print(f'{env} repetition={rep}/3 complete', flush=True)
        meta['collection_status'] = 'COMPLETE_PENDING_ANALYSIS'
    except Exception as exc:
        meta['error'] = type(exc).__name__ + ': ' + str(exc)
        print('STOP: ' + meta['error'])
    finally:
        password = None
        meta['completed_utc'] = datetime.now(timezone.utc).isoformat()
        (out / 'run_metadata.json').write_text(json.dumps(meta, indent=2))
        (out / 'SHA256SUMS').write_text(''.join(f'{sha(p)}  {p.name}\n' for p in sorted(out.iterdir()) if p.is_file()))
    for (env, role, status), count in sorted(counts.items()):
        print(f'{env} {role} HTTP={status} observations={count}')
    print('Collection_status=' + meta['collection_status'])
    print('Evidence_directory=' + str(out))
    return 0 if meta['collection_status'] == 'COMPLETE_PENDING_ANALYSIS' else 1

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline-dir', type=Path, required=True)
    parser.add_argument('--browser-results', type=Path, required=True)
    parser.add_argument('--run', action='store_true', help='Send matched tests to the three local WAF paths')
    args = parser.parse_args()
    cases = validate(args.baseline_dir, args.browser_results)
    print('Evidence_gate=PASS attacks=21 controls=4; planned=225 observations')
    return collect(cases, args.baseline_dir, args.browser_results) if args.run else 0

if __name__ == '__main__':
    raise SystemExit(main())
