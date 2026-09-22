#!/usr/bin/env python3
"""Explicit transport checks and baseline evidence collection for the local lab."""
import argparse
import getpass
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, quote_plus, urlsplit
import requests
from legacy_v10 import login

ROOT = Path(__file__).resolve().parent
BASE = 'http://waf-lab.local:8081'

def encode(value, mode):
    if mode == 'percent_once':
        return quote(value, safe='')
    if mode == 'form_plus':
        return quote_plus(value, safe='')
    if mode == 'percent_twice':
        return quote(quote(value, safe=''), safe='')
    if mode == 'literal_slash':
        return quote(value, safe='/')
    raise ValueError('Unknown encoding mode: ' + mode)

def prepare(session, item, run_id, repetition):
    body = quote(item['parameter'], safe='') + '=' + encode(item['payload'], item['encoding'])
    if item['category'] in ('sqli', 'command_injection'):
        body += '&Submit=Submit'
    headers = {'X-WAF-Test-ID': item['case_id'], 'X-WAF-Run-ID': run_id,
               'X-WAF-Repetition': str(repetition), 'User-Agent': 'COMP6016-Corrected-v11/1.0'}
    url = BASE + item['endpoint']
    if item['method'] == 'POST':
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        req = requests.Request('POST', url, data=body, headers=headers)
    else:
        req = requests.Request('GET', url + '?' + body, headers=headers)
    prepared = session.prepare_request(req)
    actual = prepared.body if item['method'] == 'POST' else urlsplit(prepared.url).query
    if actual != body:
        raise ValueError('Client changed the intended transport for ' + item['case_id'])
    return prepared, body

def check(cases):
    # This method prepares requests only. There is no Session.send here.
    with requests.Session() as session:
        forms = {c['case_id']: prepare(session, c, 'offline-only', 1)[1] for c in cases}
    assert '%20' in forms['R11-SQLI-E01']
    assert '+' in forms['R11-SQLI-E02'] and '%20' not in forms['R11-SQLI-E02']
    assert '%2527' in forms['R11-SQLI-E03']
    assert len({forms['R11-SQLI-E0' + str(i)] for i in (1, 2, 3)}) == 3
    assert '%20' in forms['R11-CMD-E01'] and '+' in forms['R11-CMD-E02']
    assert '%0A' in forms['R11-CMD-E03']
    assert '../' in forms['R11-PTH-E01']
    assert '%2F' in forms['R11-PTH-E02'] and '%252F' in forms['R11-PTH-E03']
    assert len({forms['R11-PTH-E0' + str(i)] for i in (1, 2, 3)}) == 3
    print('Offline_transport_check=PASS cases=' + str(len(cases)))
    print('Distinct_transports=SQLi(3), command_separator(2), path(3)')
    print('HTTP_requests_sent=0')

def safe_headers(headers):
    return {k: v for k, v in headers.items()
            if k.lower() not in ('cookie', 'set-cookie', 'authorization', 'proxy-authorization')}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline', action='store_true', help='Send candidate cases to baseline only')
    args = parser.parse_args()
    cases = json.loads((ROOT / 'catalogue.json').read_text())
    check(cases)
    if not args.baseline:
        return 0
    password = getpass.getpass('DVWA password: ')
    if not password:
        raise SystemExit('No password entered; nothing sent.')
    run_id = 'r11-baseline-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    out = ROOT / 'evidence' / run_id
    out.mkdir(parents=True, exist_ok=False)
    meta = {'run_id': run_id, 'phase': 'baseline', 'started_utc': datetime.now(timezone.utc).isoformat(),
            'baseline_url': BASE, 'catalogue_sha256': hashlib.sha256((ROOT / 'catalogue.json').read_bytes()).hexdigest(),
            'cases_planned': len(cases), 'cases_sent': 0, 'xml': 'NOT_EXECUTED',
            'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    print('Evidence_directory=' + str(out), flush=True)
    rows = []
    failed = False
    with requests.Session() as session:
        session.trust_env = False
        try:
            auth = login(session, BASE, 'admin', password)
            # The inherited helper returns a full prepared Cookie header: never save it.
            auth.get('security', {}).pop('cookie_header_for_prepared_probe', None)
            meta['authentication'] = auth
            if not auth.get('passed'):
                raise RuntimeError('Authentication/security-cookie gate failed; no test cases sent')
            meta['security_verification'] = 'outgoing_cookie_only; baseline effects require separate validation'
            for c in cases:
                stem = c['case_id']
                row = {'run_id': run_id, 'case_id': stem, 'category': c['category'],
                       'encoding': c['encoding'], 'repetition': 1, 'ground_truth': 'PENDING_REVIEW'}
                try:
                    req, wire = prepare(session, c, run_id, 1)
                    request_record = {'method': req.method, 'url': req.url,
                                      'headers': safe_headers(req.headers), 'body': req.body,
                                      'intended_encoded_parameter_string': wire}
                    request_path = out / (stem + '.request.json')
                    request_path.write_text(json.dumps(request_record, indent=2) + '\n')
                    row['request_sha256'] = hashlib.sha256(request_path.read_bytes()).hexdigest()
                    meta['cases_sent'] += 1
                    response = session.send(req, timeout=15, allow_redirects=False)
                    body_path = out / (stem + '.body.html')
                    body_path.write_bytes(response.content)
                    row.update(http_status=response.status_code, elapsed_seconds=response.elapsed.total_seconds(),
                               response_sha256=hashlib.sha256(response.content).hexdigest(),
                               response_headers=safe_headers(response.headers),
                               marker_present=bool(c.get('marker') and c['marker'] in response.text),
                               sql_record_labels=len(re.findall(r'First name:', response.text, re.I)))
                    print(f"{stem} HTTP={response.status_code} marker={row['marker_present']} records={row['sql_record_labels']}", flush=True)
                    if response.status_code in (301, 302, 303, 307, 308) or 'name="password"' in response.text:
                        raise RuntimeError('Redirect/login response; stop for review')
                except Exception as exc:
                    row['error'] = type(exc).__name__ + ': ' + str(exc)
                    failed = True
                rows.append(row)
                with (out / 'results.jsonl').open('a') as handle:
                    handle.write(json.dumps(row) + '\n')
                if failed:
                    break
        except Exception as exc:
            meta['error'] = type(exc).__name__ + ': ' + str(exc)
            failed = True
        finally:
            password = None
            meta['completed_utc'] = datetime.now(timezone.utc).isoformat()
            meta['observations'] = len(rows)
            meta['collection_status'] = 'INCOMPLETE' if failed else 'COMPLETE_UNVALIDATED'
            (out / 'run_metadata.json').write_text(json.dumps(meta, indent=2) + '\n')
    print('Collection_status=' + meta['collection_status'])
    print('Ground_truth=PENDING_REVIEW; protected_requests_sent=0')
    print('Evidence_directory=' + str(out))
    return 1 if failed else 0

if __name__ == '__main__':
    raise SystemExit(main())
