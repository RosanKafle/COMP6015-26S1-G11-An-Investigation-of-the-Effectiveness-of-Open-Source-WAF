"""Software tests only. Synthetic fixtures live in temporary directories, never experiment folders."""
from __future__ import annotations
import argparse
from dataclasses import asdict, replace
import csv
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
WEEK = ROOT / 'Week_07'
sys.path[:0] = [str(WEEK / 'scripts'), str(WEEK / 'analysis')]
from lab_http import request, validate_url, validate_endpoint
from config_loader import Config, load_config, environment
from classification import classify
from test_loader import TestCase, load_tests as load_cases
from request_runner import execute, encode_fields
from result_writer import FIELDS
from result_reader import read_results, one_condition, NO_RESULTS
from apply_evidence import apply
from generate_variants import generate
from payload_variants import transform_case
from metrics import calculate
from category_summary import summarize
from confusion_matrix import matrix
from missed_detection_analysis import extract
from generate_analysis_report import generate as report, paired
from merge_results import merge
from run_test_set import run


class StubHandler(BaseHTTPRequestHandler):
    """Controlled loopback software fixture; this is not DVWA or a WAF."""
    seen = []

    def do_GET(self):
        type(self).seen.append(self.path)
        if self.path.startswith('/redirect'):
            self.send_response(302)
            self.send_header('Location', 'https://example.invalid/do-not-follow')
        elif self.path.startswith('/blocked'):
            self.send_response(403)
        else:
            self.send_response(200)
        self.end_headers()
        self.wfile.write(b'UNIT TEST FIXTURE ONLY')

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.do_GET()

    def log_message(self, *args):
        pass


class FrameworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), StubHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='waf_UNIT_TEST_ONLY_')
        self.directory = Path(self.temp.name)
        self.config = Config(self.url, 'modsecurity', 2, 0.05,
                             self.directory / 'raw', self.directory / 'logs', True)

    def tearDown(self):
        self.temp.cleanup()

    def fixture_rows(self, waf='modsecurity'):
        """Labelled synthetic cases for logic testing; not claimed experimental outcomes."""
        examples = [('MALICIOUS', 'BLOCKED', 'TP'), ('MALICIOUS', 'ALLOWED', 'FN'),
                    ('NORMAL', 'BLOCKED', 'FP'), ('NORMAL', 'ALLOWED', 'TN'),
                    ('MALICIOUS', 'UNKNOWN', 'UNKNOWN')]
        rows = []
        for i, (expected, action, classification) in enumerate(examples):
            row = {k: '' for k in FIELDS}
            row.update(run_id='UNIT_TEST_ONLY_' + waf, timestamp=datetime.now(timezone.utc).isoformat(),
                       waf=waf, test_id=f'FIXTURE{i}', request_id=f'FIXTURE_REQUEST{i}',
                       category='sqli' if expected == 'MALICIOUS' else 'normal',
                       variant='baseline', expected_class=expected, method='GET', endpoint='/',
                       http_status='200', response_length='0', waf_action=action,
                       classification=classification, notes='SYNTHETIC UNIT TEST ONLY',
                       test_set_sha256='a'*64, case_sha256=str(i)*64,
                       execution_status='SENT', evidence_reference='synthetic unit-test decision',
                       wire_encoding='form', review_status='BASELINE', payload='UNIT_TEST', parameter='q')
            rows.append(row)
        return rows

    def save_rows(self, name, rows):
        path = self.directory / name
        with path.open('w', newline='', encoding='utf-8') as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def test_allowlist_and_url_escape_rejection(self):
        for url in ['http://localhost:8888/DVWA', 'http://10.0.0.1', 'http://172.16.0.1',
                    'http://172.31.255.254', 'http://192.168.2.2', 'http://[::1]']:
            self.assertTrue(validate_url(url))
        for url in ['https://203.0.113.7', 'http://172.32.0.1', 'http://169.254.169.254',
                    'http://0.0.0.0', 'http://192.0.0.1', 'file:///tmp/a',
                    'http://lab.internal', 'http://2130706433', 'http://localhost.example.invalid',
                    'http://127.0.0.1@203.0.113.7', 'http://127.0.0.1/?url=x', 'http://[fc00::1]',
                    'http://127.0.0.1:99999', 'http://127.0.0.1\\@203.0.113.7']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_url(url)
        for endpoint in ['//203.0.113.7/', 'https://203.0.113.7/', '/x?url=y', '/x\nHost: x']:
            with self.assertRaises(ValueError):
                validate_endpoint(endpoint)

    def test_transport_redirect_proxy_and_response_limit(self):
        StubHandler.seen = []
        with patch.dict(os.environ, {'HTTP_PROXY': 'http://invalid.example:1'}):
            response = request(self.url, '/redirect', max_bytes=5)
        self.assertEqual(response.status, 302)
        self.assertEqual(StubHandler.seen, ['/redirect'])
        self.assertTrue(response.truncated)
        self.assertEqual(len(response.body), 5)

    def test_environment_check_is_real_http_only_and_no_overwrite(self):
        from check_environment import check
        config = self.directory / 'environment.json'
        config.write_text(json.dumps({'components': {'stub': self.url}, 'timeout': 2}))
        output = self.directory / 'check.csv'
        rows = check(config, output)
        self.assertTrue(rows[0]['reachable'])
        self.assertEqual(rows[0]['http_status'], 200)
        with self.assertRaises(FileExistsError):
            check(config, output)

    def test_config_environment_precedence_and_validation(self):
        config = json.loads((WEEK / 'config/modsecurity.example.json').read_text())
        path = self.directory / 'config.json'
        path.write_text(json.dumps(config))
        envfile = self.directory / '.env'
        envfile.write_text('TARGET_URL=http://10.0.0.2\nLAB_COOKIE=unit-test-secret\n')
        with patch.dict(os.environ, {'MODSECURITY_URL': self.url}, clear=True):
            loaded = load_config(path, envfile)
            self.assertEqual(loaded.target_url, self.url)
            self.assertNotIn('unit-test-secret', repr(loaded))
        for key, value in [('timeout', 'NaN'), ('delay_between_requests', 0),
                           ('lab_reviewed', 'false'), ('max_response_bytes', True)]:
            broken = dict(config, **{key: value})
            path.write_text(json.dumps(broken))
            with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
                load_config(path)
        envfile.write_text('UNSUPPORTED=bad\n')
        with self.assertRaises(ValueError):
            environment(envfile)

    def test_baseline_counts_and_duplicate_rejection(self):
        cases = load_cases(WEEK / 'test_cases')
        self.assertEqual(len(cases), 600)
        self.assertEqual(sum(c.category == 'normal' for c in cases), 120)
        folder = self.directory / 'cases'
        folder.mkdir()
        content = (WEEK / 'test_cases/normal.csv').read_text()
        (folder / 'one.csv').write_text(content)
        (folder / 'two.csv').write_text(content)
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            load_cases(folder)
        (folder / 'two.csv').write_text('wrong,columns\na,b\n')
        with self.assertRaisesRegex(ValueError, 'missing required'):
            load_cases(folder)

    def test_all_classification_mappings_and_unknown(self):
        for expected, action, result in [('MALICIOUS','BLOCKED','TP'), ('MALICIOUS','ALLOWED','FN'),
                                         ('NORMAL','BLOCKED','FP'), ('NORMAL','ALLOWED','TN'),
                                         ('NORMAL','UNKNOWN','UNKNOWN'), ('MALICIOUS','UNKNOWN','UNKNOWN')]:
            self.assertEqual(classify(expected, action), result)
        with self.assertRaises(ValueError):
            classify('MALICIOUS', '403')

    def test_403_remains_unknown_and_cookie_not_archived(self):
        case = replace(load_cases(WEEK / 'test_cases')[0], endpoint='/blocked', test_id='FIXTURE403')
        config = replace(self.config, cookie='SESSION=synthetic-unit-test-secret')
        row = execute(case, config, 'UNIT_TEST_ONLY', 'a'*64, self.directory)
        self.assertEqual(row['http_status'], 403)
        self.assertEqual(row['waf_action'], 'UNKNOWN')
        self.assertEqual(row['classification'], 'UNKNOWN')
        self.assertEqual(row['execution_status'], 'SENT')
        self.assertNotIn('synthetic-unit-test-secret', (self.directory / row['request_file']).read_text())

    def test_skips_and_connection_errors_remain_unknown(self):
        case = load_cases(WEEK / 'test_cases')[0]
        with patch('request_runner.request', side_effect=ConnectionError('unit-test')):
            row = execute(case, self.config, 'UNIT_TEST_ONLY', 'a'*64, self.directory)
        self.assertEqual((row['execution_status'], row['classification']), ('ERROR', 'UNKNOWN'))
        for changed in [replace(case, payload='PLACEHOLDER_REQUIRES_FIXTURE'),
                        replace(case, review_status='REQUIRES_REVIEW')]:
            with patch('request_runner.request') as sender:
                row = execute(changed, self.config, 'UNIT_TEST_ONLY', 'a'*64, self.directory)
                sender.assert_not_called()
            self.assertEqual(row['execution_status'], 'SKIPPED')

    def test_variants_preserve_parent_and_correct_encoding_layer(self):
        case = next(c for c in load_cases(WEEK / 'test_cases') if c.category == 'sqli')
        encoded = transform_case(case, 'urlenc')
        double = transform_case(case, 'doubleenc')
        self.assertEqual(encoded.parent_test_id, case.test_id)
        self.assertEqual(encoded.review_status, 'REQUIRES_REVIEW')
        self.assertEqual(encode_fields(case), encode_fields(encoded))
        self.assertIn('%25', encode_fields(double))
        folder = self.directory / 'cases'
        folder.mkdir()
        for file in (WEEK / 'test_cases').glob('*.csv'):
            (folder / file.name).write_bytes(file.read_bytes())
        before = {p.name: p.read_bytes() for p in folder.glob('*.csv')}
        output = folder / 'variants/generated_variants.csv'
        count = generate(folder, output, ['case', 'urlenc', 'doubleenc'])
        self.assertGreater(count, 0)
        self.assertEqual(len(load_cases(folder, True)), 600 + count)
        self.assertEqual(before, {p.name:p.read_bytes() for p in folder.glob('*.csv')})
        with self.assertRaises(FileExistsError):
            generate(folder, output, ['case'])
        with self.assertRaises(ValueError):
            generate(folder, folder / 'sqli.csv', ['case'])

    def test_plan_sends_nothing_and_checks_digest(self):
        args = argparse.Namespace(config=WEEK / 'config/test_config.json', env_file=None,
                                  category='all', test_directory=WEEK / 'test_cases',
                                  include_variants=False, expect_test_set_sha256=None, execute=False)
        with patch.dict(os.environ, {}, clear=True), patch('run_test_set.execute') as sender:
            self.assertIsNone(run(args))
            sender.assert_not_called()
            args.expect_test_set_sha256 = 'wrong'
            with self.assertRaisesRegex(ValueError, 'differs'):
                run(args)

    def test_real_loopback_collection_pipeline_is_isolated(self):
        config = json.loads((WEEK / 'config/test_config.json').read_text())
        config.update(target_url=self.url, waf_name='baseline', lab_reviewed=True, transport='direct', auth_mode='none',
                      results_directory=str(self.directory / 'UNIT_TEST_ONLY'), delay_between_requests=0.05)
        config_path = self.directory / 'config.json'
        config_path.write_text(json.dumps(config))
        cases = self.directory / 'cases'
        cases.mkdir()
        case = next(c for c in load_cases(WEEK / 'test_cases') if c.category == 'normal')
        with (cases / 'normal.csv').open('w', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=list(asdict(case)))
            writer.writeheader()
            writer.writerow(asdict(case))
        args = argparse.Namespace(config=config_path, env_file=None, category='normal',
                                  test_directory=cases, include_variants=False,
                                  expect_test_set_sha256=None, execute=True)
        with patch.dict(os.environ, {}, clear=True):
            output = run(args)
        rows = read_results(output)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['classification'], 'UNKNOWN')
        completion = json.loads((output.parent / 'completion.json').read_text())
        self.assertTrue(completion['completed'])
        self.assertTrue((output.parent / 'manifest.json').is_file())

    def test_evidence_join_is_immutable_and_request_specific(self):
        rows = self.fixture_rows()
        for row in rows:
            row.update(waf_action='UNKNOWN', classification='UNKNOWN', evidence_reference='')
        source = self.save_rows('raw.csv', rows)
        before = source.read_bytes()
        evidence = self.directory / 'evidence.csv'
        from apply_evidence import EVIDENCE_FIELDS
        with evidence.open('w', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=EVIDENCE_FIELDS)
            writer.writeheader()
            writer.writerow({k: ({**rows[0], 'waf_action':'BLOCKED', 'evidence_reference':'UNIT TEST ONLY',
                                  'notes':'synthetic fixture decision'})[k] for k in EVIDENCE_FIELDS})
        output = self.directory / 'reviewed.csv'
        apply(source, evidence, output)
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual(read_results(output)[0]['classification'], 'TP')
        self.assertEqual(read_results(output)[1]['classification'], 'UNKNOWN')
        evidence.write_text(evidence.read_text().replace('FIXTURE_REQUEST0', 'WRONG_REQUEST'))
        with self.assertRaisesRegex(ValueError, 'different run/request'):
            apply(source, evidence, self.directory / 'bad.csv')

    def test_metrics_unknown_and_zero_denominators(self):
        rows = self.fixture_rows()
        result = calculate(rows)
        for key in ('TP', 'TN', 'FP', 'FN', 'UNKNOWN'):
            self.assertEqual(result[key], 1)
        for key in ('detection_rate','false_negative_rate','false_positive_rate','normal_allow_rate'):
            self.assertEqual(result[key], 0.5)
            self.assertIsNone(calculate([])[key])
        self.assertEqual(summarize(rows)[0]['total_malicious'], 3)
        self.assertEqual(summarize(rows)[0]['detection_rate'], 0.5)

    def test_result_validation_rejects_false_classification_and_mixed_runs(self):
        rows = self.fixture_rows()
        rows[0]['classification'] = 'FN'
        with self.assertRaisesRegex(ValueError, 'Inconsistent'):
            read_results(self.save_rows('bad.csv', rows))
        with self.assertRaises(ValueError):
            one_condition(self.fixture_rows() + self.fixture_rows('naxsi'))
        rows = self.fixture_rows()
        rows[0]['execution_status'] = 'SKIPPED'
        with self.assertRaises(ValueError):
            read_results(self.save_rows('skipped.csv', rows))

    def test_merge_requires_identical_corpus_and_provenance(self):
        left = self.save_rows('mod.csv', self.fixture_rows())
        right = self.save_rows('naxsi.csv', self.fixture_rows('naxsi'))
        output = self.directory / 'merged.csv'
        merge(left, right, output)
        with output.open(newline='') as handle:
            self.assertEqual(len(list(csv.DictReader(handle))), 5)
        broken = self.fixture_rows('naxsi')
        broken[0]['case_sha256'] = 'b'*64
        self.save_rows('naxsi.csv', broken)
        with self.assertRaisesRegex(ValueError, 'content differs'):
            merge(left, right, self.directory / 'refused.csv')

    def test_analysis_reports_use_only_supplied_rows(self):
        source = self.save_rows('SYNTHETIC_UNIT_TEST.csv', self.fixture_rows())
        output = self.directory / 'report.md'
        report(source, output)
        text = output.read_text(encoding='utf-8')
        self.assertEqual(text.count('## '), 9)
        self.assertIn('No variant rows supplied', text)
        missed = self.directory / 'missed.csv'
        extract(read_results(source), missed)
        with missed.open(newline='') as handle:
            self.assertEqual([r['test_id'] for r in csv.DictReader(handle)], ['FIXTURE1'])
        matrix(read_results(source), self.directory / 'matrix.csv')

    def test_no_result_no_report_and_pairing(self):
        output = self.directory / 'must_not_exist.md'
        with self.assertRaisesRegex(ValueError, 'No real experiment result file was supplied'):
            report(None, output)
        self.assertFalse(output.exists())
        process = subprocess.run([sys.executable, str(WEEK / 'analysis/generate_analysis_report.py')],
                                 capture_output=True, text=True)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn(NO_RESULTS, process.stderr)
        rows = self.fixture_rows()
        variant = dict(rows[1], test_id='FIXTURE_VARIANT', parent_test_id='FIXTURE0', transformation='case')
        self.assertEqual(paired(rows + [variant])['blocked_to_allowed'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
