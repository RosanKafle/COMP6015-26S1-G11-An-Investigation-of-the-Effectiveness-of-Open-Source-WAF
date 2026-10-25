"""Synthetic unit fixtures only; no DVWA/WAF observations are represented by these tests."""
from pathlib import Path
from dataclasses import replace, asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import csv
import json
import re
import sys
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
WEEK = ROOT / "experiments/modsecurity-naxsi/implementation"
sys.path[:0] = [str(WEEK/"scripts"), str(WEEK/"analysis")]
from config_loader import Config, environment
from dvwa_session import DVWASession
from zap_client import ZapClient
from request_runner import execute
from test_loader import TestCase, load_tests as load_cases
from run_test_set import run, parser_for
from result_writer import FIELDS
from parse_modsecurity_audit import extract, transactions
from apply_evidence import apply
from latency_summary import summarise
from zap_active_pipeline import scope_regex, scan
from build_mixed_corpus import build

class ProxyFixture(BaseHTTPRequestHandler):
    """Emulates ZAP proxy/API and a login page without contacting any target."""
    seen = []
    session_valid = False
    def log_message(self, *args):
        pass
    def do_GET(self):
        self.handle_request("")
    def do_POST(self):
        self.handle_request(self.rfile.read(int(self.headers.get("Content-Length",0))).decode())
    def handle_request(self, body):
        type(self).seen.append((self.command, self.path, dict(self.headers), body))
        path = urlsplit(self.path).path
        status, response, cookie = 200, b"UNIT_TEST_ONLY", None
        if path == "/JSON/core/view/version/":
            response = b'{"version":"UNIT_TEST_ONLY"}'
        elif path.endswith("/login.php") and self.command == "GET":
            response = b'<input type="hidden" name="user_token" value="FIXTURE_TOKEN">'
            cookie = "PHPSESSID=FIXTURE_PRELOGIN; Path=/"
        elif path.endswith("/login.php"):
            values = parse_qs(body)
            if values.get("user_token") != ["FIXTURE_TOKEN"] or values.get("password") != ["FIXTURE_PASSWORD"]:
                status = 401
            else:
                type(self).session_valid = True
                status, cookie = 302, "PHPSESSID=FIXTURE_AUTHENTICATED; Path=/"
        elif path.endswith("/index.php"):
            cookie_header = self.headers.get("Cookie","")
            if self.session_valid and "PHPSESSID=FIXTURE_AUTHENTICATED" in cookie_header:
                response = b'<a href="logout.php">Logout</a>'
            else:
                status = 302
        elif path.endswith("/redirect"):
            status = 302
        self.send_response(status)
        if status == 302:
            self.send_header("Location", "http://example.invalid/DO_NOT_FOLLOW_UNIT_TEST")
        if cookie:
            self.send_header("Set-Cookie",cookie)
        self.send_header("Content-Length",str(len(response)))
        self.end_headers()
        self.wfile.write(response)

class ContinuationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1",0),ProxyFixture)
        cls.thread = threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="WAF_UNIT_TEST_ONLY_")
        self.folder = Path(self.temp.name)
        self.proxy = f"http://127.0.0.1:{self.server.server_port}"
        self.config = Config("http://127.0.0.1:9/DVWA","modsecurity",2,0.05,
                             self.folder/"raw",self.folder/"logs",True,
                             transport="zap",zap_url=self.proxy,auth_mode="password",
                             username="FIXTURE_USER",password="FIXTURE_PASSWORD",
                             zap_api_key="FIXTURE_API_KEY")
        ProxyFixture.seen=[]; ProxyFixture.session_valid=False
    def tearDown(self):
        self.temp.cleanup()

    def test_real_proxy_session_token_login_renewal_and_redirect_refusal(self):
        c = replace(self.config,cookie="PHPSESSID=STALE_UNIT_FIXTURE")
        client = DVWASession(c)
        try:
            self.assertEqual(ZapClient(c).version(),"UNIT_TEST_ONLY")
            client.login()
            self.assertTrue(client.check())
            case = TestCase("UNIT_NORMAL","normal","baseline","GET","/redirect","","","NORMAL","Synthetic")
            row = execute(case,c,"UNIT_TEST_ONLY","a"*64,self.folder,client)
            self.assertEqual(row["http_status"],302)
            self.assertEqual(row["classification"],"UNKNOWN")
            self.assertGreaterEqual(row["response_time_seconds"],0)
            sent = [x for x in ProxyFixture.seen if x[1].endswith("/redirect")][0]
            self.assertIn("FIXTURE_AUTHENTICATED",sent[2]["Cookie"])
            self.assertNotIn("STALE_UNIT_FIXTURE",sent[2]["Cookie"])
            self.assertTrue(sent[1].startswith("http://127.0.0.1:9/"))
            self.assertIn("Mozilla",sent[2]["User-Agent"])
            self.assertFalse(any("example.invalid" in x[1] for x in ProxyFixture.seen))
            ProxyFixture.session_valid=False
            client.ensure_authenticated()
            self.assertEqual(client.renewals,2)
            text="".join(p.read_text(errors="ignore") for p in self.folder.glob("*") if p.is_file())
            self.assertNotIn("FIXTURE_PASSWORD",text)
            self.assertNotIn("FIXTURE_AUTHENTICATED",text)
        finally:
            client.close()

    def test_cookie_mode_and_wrong_password_fail_closed(self):
        for c in (replace(self.config,password="WRONG"),replace(self.config,auth_mode="cookie",cookie="PHPSESSID=BAD")):
            client=DVWASession(c)
            try:
                with self.assertRaises(ValueError):
                    client.login()
            finally:
                client.close()

    def test_empty_normal_query_and_post_preserve_original_form(self):
        from request_runner import encode_fields
        cases=load_cases(WEEK/"test_cases")
        normal=next(c for c in cases if c.category=="normal" and not c.parameter)
        command=next(c for c in cases if c.category=="command_injection")
        self.assertEqual(encode_fields(normal),"")
        self.assertEqual(command.method,"POST")
        self.assertIn("Submit=Submit",encode_fields(command))
        self.assertIn("WAF_LAB_MARKER",command.payload)

    def test_seeded_corpus_repeatability_and_category_balance(self):
        templates=json.loads((WEEK/"config/inherited_test_templates.json").read_text())
        a=build(templates,self.folder/"a",120,2026)
        b=build(templates,self.folder/"b",120,2026)
        self.assertEqual(a,b)
        self.assertEqual(len({r["test_id"] for r in a}),600)
        for category in ("normal","sqli","xss","command_injection","path_traversal"):
            self.assertEqual(sum(r["category"]==category for r in a),120)
        self.assertNotEqual(a,build(templates,self.folder/"c",120,2027))
        with self.assertRaises(FileExistsError):
            build(templates,self.folder/"a")

    def test_secret_quotes_are_preserved(self):
        p=self.folder/".env"
        p.write_text("DVWA_PASSWORD=secret'\nZAP_API_KEY=\"quoted\"\n")
        with patch.dict("os.environ",{},clear=True):
            values=environment(p)
        self.assertEqual(values["DVWA_PASSWORD"],"secret'")
        self.assertEqual(values["ZAP_API_KEY"],"quoted")

    def test_native_parser_only_reads_headers_and_audit_messages(self):
        raw=self.folder/"raw.csv"
        row={k:"" for k in FIELDS}
        row.update(run_id="UNIT_TEST_ONLY",waf="modsecurity",test_id="T1",request_id="RID1",
                   expected_class="MALICIOUS",category="sqli",classification="UNKNOWN",waf_action="UNKNOWN",
                   timestamp="2026-01-01T00:00:00+00:00",test_set_sha256="a"*64,case_sha256="b"*64,
                   execution_status="SENT",http_status="403")
        with raw.open("w",newline="") as f:
            writer=csv.DictWriter(f,fieldnames=FIELDS); writer.writeheader(); writer.writerow(row)
        audit=self.folder/"UNIT_TEST_ONLY.log"
        audit.write_text('--tx1-A--\nheader\n--tx1-B--\nGET / HTTP/1.1\nX-Lab-Request-ID: RID1\n'
                         '--tx1-C--\nMessage: [id "999999"]\n'
                         '--tx1-H--\nMessage: Warning. [id "942100"]\n'
                         'Message: Access denied with code 403 (phase 2). [id "949110"]\n--tx1-Z--\n')
        extract(raw,audit,self.folder/"parsed")
        with (self.folder/"parsed/rule_events.csv").open() as handle:
            events=list(csv.DictReader(handle))
        self.assertEqual({r["rule_id"] for r in events},{"942100","949110"})
        with self.assertRaisesRegex(ValueError,"Unreviewed block candidate"):
            apply(raw,self.folder/"parsed/block_candidates.csv",self.folder/"reviewed.csv")
        self.assertEqual(len(list(transactions(audit.read_text().replace("--tx1-Z--","")))),0)

    def test_active_scope_rejects_external_and_state_changing_routes(self):
        regex=scope_regex("http://192.168.56.20/DVWA")
        self.assertTrue(re.fullmatch(regex,"http://192.168.56.20/DVWA/vulnerabilities/sqli/?id=1"))
        for url in ("http://192.168.56.20/DVWA/setup.php","http://192.168.56.20/DVWA/logout.php",
                    "http://192.168.56.200/DVWA/index.php","http://example.invalid/DVWA/index.php"):
            self.assertFalse(re.fullmatch(regex,url))
        with patch("zap_active_pipeline.ZapClient") as api:
            with self.assertRaises(ValueError):
                scan(self.config,self.folder/"scan")
            api.assert_not_called()

    def test_full_collection_uses_proxy_and_does_not_archive_passwords(self):
        case=TestCase("UNIT_NORMAL","normal","baseline","GET","/index.php","","","NORMAL","Synthetic")
        cases=self.folder/"cases";cases.mkdir()
        with (cases/"normal.csv").open("w",newline="") as f:
            w=csv.DictWriter(f,fieldnames=list(asdict(case)));w.writeheader();w.writerow(asdict(case))
        config=json.loads((WEEK/"config/test_config.json").read_text())
        config.update(target_url=self.config.target_url,zap_url=self.proxy,lab_reviewed=True,
                      results_directory=str(self.folder/"raw"))
        cfg=self.folder/"cfg.json";cfg.write_text(json.dumps(config))
        env=self.folder/".env";env.write_text("DVWA_USERNAME=FIXTURE_USER\nDVWA_PASSWORD=FIXTURE_PASSWORD\nZAP_API_KEY=FIXTURE_API_KEY\n")
        args=parser_for().parse_args(["--config",str(cfg),"--env-file",str(env),"--test-directory",str(cases),"--execute"])
        with patch.dict("os.environ",{},clear=True):
            output=run(args)
        manifest=(output.parent/"manifest.json").read_text()
        for secret in ("FIXTURE_PASSWORD","FIXTURE_USER","FIXTURE_API_KEY"):
            self.assertNotIn(secret,manifest)
        self.assertTrue(json.loads((output.parent/"completion.json").read_text())["completed"])

    def test_latency_missing_stays_missing(self):
        self.assertIsNone(summarise([{"execution_status":"SENT","response_time_seconds":""}])["median_seconds"])
        result=summarise([{"execution_status":"SENT","response_time_seconds":str(n)} for n in (1,2,3)])
        self.assertEqual(result["median_seconds"],2)
        with self.assertRaises(ValueError):
            summarise([{"execution_status":"SENT","response_time_seconds":"NaN"}])

    def test_active_pipeline_exports_only_scan_ids_and_cleans_up(self):
        from unittest.mock import MagicMock
        api=MagicMock()
        api.version.return_value="UNIT_TEST_ONLY"
        calls=[]
        def call(component,kind,action,**params):
            calls.append((component,kind,action,params))
            if action=="scanners":return {"scanners":[{"id":"40018"}]}
            if action=="contextList":return {"contextList":[]}
            if action=="scans":return {"scans":[]}
            if action=="newContext":return {"contextId":"FIXTURE_CONTEXT"}
            if action=="scan":return {"scan":str(len(calls))}
            if action=="status":return {"status":"100"}
            if action=="messagesIds":return {"messagesIds":["1"]}
            if action=="alertsIds":return {"alertsIds":["2"]}
            if action=="message":return {"message":{"requestHeader":"GET / HTTP/1.1\nCookie: FIXTURE_SECRET","responseHeader":"HTTP/1.1 200 OK\nSet-Cookie: FIXTURE_SECRET","responseBody":"UNIT_TEST_ONLY"}}
            if action=="alert":return {"alert":{"name":"UNIT_TEST_ONLY"}}
            return {"Result":"OK"}
        api.call.side_effect=call
        session=MagicMock()
        session.check.return_value=True
        session.session.cookies=[]
        session.session.headers={"User-Agent":"UNIT_TEST_ONLY"}
        c=replace(self.config,scanner_ids=("40018",),scanner_lab_reviewed=True)
        with patch("zap_active_pipeline.ZapClient",return_value=api),patch("zap_active_pipeline.DVWASession",return_value=session):
            scan(c,self.folder/"scan")
        self.assertTrue(json.loads((self.folder/"scan/completion.json").read_text())["completed"])
        self.assertNotIn("FIXTURE_SECRET",(self.folder/"scan/message-1.json").read_text())
        self.assertTrue(any(a=="removeRule" for _,_,a,_ in calls))
        self.assertTrue(any(a=="removeContext" for _,_,a,_ in calls))
        self.assertFalse(any(a in ("newSession","messages") for _,_,a,_ in calls))
        for component,kind,action,params in calls:
            if component=="ascan" and action=="scan":
                self.assertEqual(params["inScopeOnly"],"true")
                self.assertEqual(params["recurse"],"false")
        session.close.assert_called_once()

if __name__=="__main__":
    unittest.main()
