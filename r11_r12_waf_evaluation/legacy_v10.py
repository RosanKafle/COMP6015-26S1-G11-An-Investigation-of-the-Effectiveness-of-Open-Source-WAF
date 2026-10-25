#!/usr/bin/env python3
"""Baseline-gated runner for the WAF expansion catalogue.

Run this on Kali, not on the Ubuntu WAF host. It deliberately separates a
baseline phase from protected execution so a request is not called a bypass
before its intended application effect is demonstrated.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus, urlparse

import requests


BASE_URLS = {
    'baseline': 'http://waf-lab.local:8081',
    'modsec': 'http://waf-lab.local',
    'coraza': 'http://waf-lab.local:8080',
    'naxsi': 'http://waf-lab.local:8084',
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def marker_for(case_id: str, payload: str) -> str | None:
    m = re.search(r'W10(?:XSS|CMD|PATH|XML)\d+', payload)
    return m.group(0) if m else None


def wire_value(case_id: str, payload: str, transport: str) -> str:
    """Create the intended query value before the client sends it.

    The prepared request saved by this runner is authoritative because a
    client/proxy may normalise the value. This helper is intentionally small
    and maps only the transformations in the catalogue.
    """
    t = transport.lower()
    if 'double' in t or 'twice' in t:
        return quote(quote(payload, safe=''), safe='')
    if 'plus' in t:
        return quote_plus(payload, safe='')
    if 'percent' in t or 'encode' in t or 'encoded' in t:
        return quote(payload, safe='')
    if case_id.endswith('E05') and 'path' in case_id:
        return payload.replace('\\', '%5C')
    if case_id.endswith('E06') and 'path' in case_id:
        return payload.replace('\\', '%5C')
    return quote(payload, safe='')


def _security_cookie_snapshot(session: requests.Session) -> list[dict[str, str]]:
    """Return every security cookie, including duplicate domain/path entries."""
    return [
        {'domain': cookie.domain, 'path': cookie.path, 'value': cookie.value}
        for cookie in session.cookies
        if cookie.name == 'security'
    ]


def set_security_low(session: requests.Session, base_url: str) -> dict[str, Any]:
    """Prepare the authenticated session for DVWA low-security testing.

    This DVWA instance returns a ``security=impossible`` cookie even after a
    successful login, while the earlier pilot used ``security=low`` for the
    intended vulnerable test mode.  The security-page POST is attempted and
    recorded, then all duplicate ``security`` cookie entries are removed and a
    host-scoped low cookie is installed.  The gate checks the Cookie header of
    a prepared (not sent) request, so no probe request is added to the
    experiment.  The override is explicitly recorded in run_metadata.json.
    """
    security_url = f'{base_url}/DVWA/security.php'
    host = urlparse(base_url).hostname or ''
    before = _security_cookie_snapshot(session)
    security_page = session.get(security_url, timeout=10, allow_redirects=True)
    token_match = re.search(
        r'name=["\']user_token["\'][^>]*value=["\']([^"\']+)',
        security_page.text,
        re.I,
    )
    post_data = {'security': 'low', 'seclev_submit': 'Submit'}
    if token_match:
        post_data['user_token'] = token_match.group(1)
    post = session.post(
        security_url,
        data=post_data,
        timeout=10,
        allow_redirects=True,
    )
    after_post = _security_cookie_snapshot(session)
    server_set_low = any(cookie['value'] == 'low' for cookie in after_post)

    # Requests can retain duplicate cookies with different domains/paths.  A
    # plain cookies.set(..., path='/') may therefore leave ``impossible`` in
    # the jar and make CookieConflictError or the wrong value win.  Clear every
    # entry first, then set one explicit host/path cookie.
    for cookie in list(session.cookies):
        if cookie.name != 'security':
            continue
        try:
            session.cookies.clear(domain=cookie.domain, path=cookie.path, name=cookie.name)
        except KeyError:
            pass
    session.cookies.set('security', 'low', domain=host, path='/')

    probe_url = f'{base_url}/DVWA/index.php'
    prepared = session.prepare_request(requests.Request('GET', probe_url))
    cookie_header = prepared.headers.get('Cookie', '')
    low_in_header = bool(re.search(r'(^|;\s*)security=low(?:;|$)', cookie_header))
    if not low_in_header:
        # Host-only fallback for unusual requests-cookiejar domain handling.
        session.cookies.set('security', 'low', path='/')
        prepared = session.prepare_request(requests.Request('GET', probe_url))
        cookie_header = prepared.headers.get('Cookie', '')
        low_in_header = bool(re.search(r'(^|;\s*)security=low(?:;|$)', cookie_header))

    return {
        'passed': low_in_header,
        'security_cookie_before': before[-1]['value'] if before else None,
        'security_cookie_after_post': after_post[-1]['value'] if after_post else None,
        'security_cookie_entries_before': before,
        'security_cookie_entries_after_post': after_post,
        'security_cookie': 'low' if low_in_header else None,
        'manual_cookie_override': not server_set_low,
        'security_page_get_http_status': security_page.status_code,
        'security_page_token_found': bool(token_match),
        'post_http_status': post.status_code,
        'cookie_header_for_prepared_probe': cookie_header,
        'probe_url_not_sent': probe_url,
    }


def login(session: requests.Session, base_url: str, username: str, password: str) -> dict[str, Any]:
    login_url = f'{base_url}/DVWA/login.php'
    first = session.get(login_url, timeout=10, allow_redirects=True)
    token_match = re.search(r'name=["\']user_token["\'][^>]*value=["\']([^"\']+)', first.text, re.I)
    data = {'username': username, 'password': password, 'Login': 'Login'}
    if token_match:
        data['user_token'] = token_match.group(1)
    response = session.post(login_url, data=data, timeout=10, allow_redirects=True)
    passed = '/login.php' not in response.url and response.status_code < 400
    security = set_security_low(session, base_url) if passed else {
        'passed': False,
        'security_cookie': None,
        'reason': 'login_failed',
    }
    return {
        'passed': passed and security.get('passed', False),
        'http_status': response.status_code,
        'final_url': response.url,
        'security_cookie': security.get('security_cookie'),
        'security': security,
    }


def request_case(session: requests.Session, base_url: str, item: dict[str, Any], run_id: str, repetition: int) -> tuple[requests.Response, str]:
    endpoint = item['endpoint']
    if endpoint.startswith('PENDING_'):
        raise RuntimeError('endpoint prerequisite is not configured')
    url = f'{base_url}{endpoint}'
    payload = item['payload_display']
    common_headers = {
        'X-WAF-Test-ID': item['case_id'],
        'X-WAF-Run-ID': run_id,
        'X-WAF-Repetition': str(repetition),
        'User-Agent': 'COMP6016-Expanded-WAF-Research/1.0',
    }
    endpoint_lower = endpoint.lower()
    if '/exec/' in endpoint_lower:
        # DVWA Command Injection's form is POST, even though older catalogue
        # rows labelled these cases as GET.  The endpoint's actual form
        # method takes precedence over a stale catalogue value.
        method = 'POST'
    elif item.get('method'):
        method = item['method']
    elif item.get('parameter') == 'body':
        method = 'POST'
    else:
        method = 'GET'
    if method.upper() == 'POST':
        if '/exec/' in endpoint_lower:
            # The DVWA handler executes only after receiving the form's
            # submit control as well as the input value.
            response = session.post(
                url,
                data={item['parameter']: payload, 'Submit': 'Submit'},
                headers=common_headers,
                timeout=10,
                allow_redirects=True,
            )
        else:
            response = session.post(
                url,
                data=payload,
                headers={**common_headers, 'Content-Type': 'application/xml'},
                timeout=10,
                allow_redirects=True,
            )
        prepared = response.request.url
        return response, prepared
    encoded = wire_value(item['case_id'], payload, item.get('transport_encoding', 'standard'))
    parameter = quote(item['parameter'], safe='')
    query = f'{parameter}={encoded}'
    if item.get('attack_class') == 'sqli':
        # DVWA's SQLi handler is guarded by the submit button name/value.
        query += '&Submit=Submit'
    prepared = f'{url}?{query}'
    response = session.get(prepared, headers=common_headers, timeout=10, allow_redirects=True)
    return response, prepared


def save_observation(root: Path, run_id: str, environment: str, item: dict[str, Any], repetition: int, response: requests.Response, prepared_url: str, phase: str) -> dict[str, Any]:
    stem = f'{item["case_id"]}__{environment}__r{repetition}'
    (root / 'requests').mkdir(parents=True, exist_ok=True)
    (root / 'responses').mkdir(parents=True, exist_ok=True)
    (root / 'metadata').mkdir(parents=True, exist_ok=True)
    request_path = root / 'requests' / f'{stem}.txt'
    headers_path = root / 'responses' / f'{stem}__headers.txt'
    body_path = root / 'responses' / f'{stem}__body.html'
    metadata_path = root / 'metadata' / f'{stem}.json'
    request_body = response.request.body or ''
    request_text = [
        f'{response.request.method} {prepared_url} HTTP/1.1',
        f'Host: {response.request.headers.get("Host", "")}',
        f'Content-Type: {response.request.headers.get("Content-Type", "")}',
        f'X-WAF-Test-ID: {response.request.headers.get("X-WAF-Test-ID", "")}',
        f'X-WAF-Run-ID: {response.request.headers.get("X-WAF-Run-ID", "")}',
        f'X-WAF-Repetition: {response.request.headers.get("X-WAF-Repetition", "")}',
        f'User-Agent: {response.request.headers.get("User-Agent", "")}',
        '',
        request_body.decode(errors='replace') if isinstance(request_body, bytes) else str(request_body),
    ]
    request_path.write_text('\n'.join(request_text), encoding='utf-8', errors='replace')
    headers_path.write_text('\n'.join(f'{k}: {v}' for k, v in response.headers.items()), encoding='utf-8', errors='replace')
    body_path.write_text(response.text, encoding='utf-8', errors='replace')
    marker = marker_for(item['case_id'], item['payload_display'])
    row = {
        'run_id': run_id,
        'phase': phase,
        'environment': environment,
        'case_id': item['case_id'],
        'attack_class': item['attack_class'],
        'family': item['family'],
        'repetition': repetition,
        'prepared_url': prepared_url,
        'http_status': response.status_code,
        'response_bytes': len(response.content),
        'elapsed_seconds': response.elapsed.total_seconds(),
        'redirect_chain': len(response.history),
        'final_url': response.url,
        'marker': marker,
        'marker_present': bool(marker and marker in response.text),
        'preliminary_outcome': 'baseline_observed' if phase == 'baseline' else ('blocked_candidate' if response.status_code in (403, 406) else 'allowed_candidate'),
        'classification': 'PENDING_LOG_CORRELATION',
        'request_file': str(request_path.relative_to(root)),
        'response_header_file': str(headers_path.relative_to(root)),
        'response_body_file': str(body_path.relative_to(root)),
        'request_sha256': hashlib.sha256(request_path.read_bytes()).hexdigest(),
        'response_body_sha256': hashlib.sha256(body_path.read_bytes()).hexdigest(),
        'server_log_reference': '',
        'rule_ids_or_scores': '',
    }
    metadata_path.write_text(json.dumps(row, indent=2) + '\n', encoding='utf-8')
    return row


def read_catalogue(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    data = json.loads(path.read_text(encoding='utf-8'))
    return data['attack_cases'], data['benign_controls']


def read_approved(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    return {line.strip() for line in path.read_text().splitlines() if line.strip() and not line.lstrip().startswith('#')}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--catalogue', default=str(Path(__file__).with_name('expanded_catalogue.json')))
    ap.add_argument('--evidence-dir', required=True)
    ap.add_argument('--phase', choices=['baseline', 'protected'], required=True)
    ap.add_argument('--approved-file', help='one baseline-approved case_id per line; required for protected phase')
    ap.add_argument('--repetitions', type=int, default=1)
    ap.add_argument('--environments', default='baseline,modsec,coraza,naxsi')
    ap.add_argument('--username', default=os.environ.get('DVWA_USERNAME', 'admin'))
    args = ap.parse_args()
    password = os.environ.get('DVWA_PASSWORD')
    if not password:
        print('DVWA_PASSWORD is required in the environment; it is never written to evidence.', file=sys.stderr)
        return 2
    if args.phase == 'protected' and not args.approved_file:
        print('--approved-file is required for protected phase', file=sys.stderr)
        return 2
    approved = read_approved(Path(args.approved_file) if args.approved_file else None)
    attack_cases, benign_controls = read_catalogue(Path(args.catalogue))
    selected = [*attack_cases, *benign_controls]
    if args.phase == 'protected':
        selected = [x for x in selected if x['case_id'] in approved]
    environments = [x.strip() for x in args.environments.split(',') if x.strip()]
    if args.phase == 'baseline':
        environments = ['baseline']
    root = Path(args.evidence_dir)
    root.mkdir(parents=True, exist_ok=True)
    run_id = f'waf-expansion-{datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")}'
    rows: list[dict[str, Any]] = []
    sessions: dict[str, requests.Session] = {}
    run_meta = {'run_id': run_id, 'phase': args.phase, 'started_utc': utc_now(), 'catalogue': str(Path(args.catalogue).resolve()), 'environments': environments, 'repetitions': args.repetitions, 'authentication': {}}
    for env in environments:
        session = requests.Session()
        sessions[env] = session
        try:
            run_meta['authentication'][env] = login(session, BASE_URLS[env], args.username, password)
        except Exception as exc:
            run_meta['authentication'][env] = {'passed': False, 'error': str(exc)}
    (root / 'run_metadata.json').write_text(json.dumps(run_meta, indent=2) + '\n', encoding='utf-8')
    for env in environments:
        if not run_meta['authentication'][env].get('passed'):
            print(f'{env}: authentication failed; no cases sent')
            continue
        for repetition in range(1, args.repetitions + 1):
            for item in selected:
                if item.get('endpoint', '').startswith('PENDING_'):
                    print(f'{item["case_id"]} {env} NOT_EXECUTED endpoint prerequisite missing')
                    continue
                try:
                    started = time.monotonic()
                    response, prepared = request_case(sessions[env], BASE_URLS[env], item, run_id, repetition)
                    row = save_observation(root, run_id, env, item, repetition, response, prepared, args.phase)
                    row['client_elapsed_seconds'] = time.monotonic() - started
                    rows.append(row)
                    print(item['case_id'], env, f'HTTP={response.status_code}', row['preliminary_outcome'])
                except Exception as exc:
                    print(item['case_id'], env, f'INDETERMINATE {exc}')
    fields = sorted({key for row in rows for key in row})
    with (root / 'results.csv').open('w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    with (root / 'results.jsonl').open('w', encoding='utf-8') as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + '\n')
    run_meta['completed_utc'] = utc_now()
    run_meta['rows_written'] = len(rows)
    (root / 'run_metadata.json').write_text(json.dumps(run_meta, indent=2) + '\n', encoding='utf-8')
    print(f'run_id={run_id} rows={len(rows)} evidence_dir={root}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
