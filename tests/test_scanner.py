import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from scan_engine import Scope, ScopeError, assess, canonical_url, redact_url
import scan_store


class Fixture(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        type(self).hits.append(self.path)
        parsed = urlsplit(self.path)
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/private")
            self.end_headers()
            return
        if parsed.path == "/slow":
            time.sleep(0.3)
        q = parse_qs(parsed.query).get("q", [""])[0]
        body = ("SQLITE_ERROR: synthetic fixture" if "'" in q else "Result " + q)
        body += '<a href="/next">next</a><a href="http://outside.invalid/">outside</a><a href="/delete">delete</a>'
        body += '<form method="post" action="/submit"><input name="password"></form>'
        if parsed.path == "/large":
            body += "x" * 300000
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Set-Cookie", "fixture=secret-value; Path=/")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *args):
        pass


OPTIONS = dict(mode="active", max_pages=3, max_requests=12, max_depth=1, delay_seconds=0.0, ai_review=False)


class ScopeTests(unittest.TestCase):
    def test_url_credentials_and_schemes(self):
        for url in ["file:///etc/passwd", "http://u:p@example.com", "http://example.com\\evil", "http://example.com\n"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                canonical_url(url)

    def test_same_origin(self):
        s = Scope("https://example.com/")
        for url in ["http://example.com", "https://example.com:444", "https://sub.example.com", "https://other.com"]:
            with self.assertRaises(ScopeError):
                s.check(url)

    def test_private_dns_and_mixed_answers_denied(self):
        s = Scope("https://example.com")
        for ips in [["127.0.0.1"], ["169.254.169.254"], ["::1"], ["93.184.216.34", "10.0.0.1"]]:
            answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ips]
            with patch("scan_engine.socket.getaddrinfo", return_value=answers), self.assertRaises(ScopeError):
                s.resolve(s.target)

    def test_secrets_and_destructive_paths(self):
        with self.assertRaises(ScopeError):
            Scope("https://example.com/?token=private")
        with self.assertRaises(ScopeError):
            Scope("https://example.com").check("https://example.com/delete")
        self.assertNotIn("private", redact_url("https://example.com/?token=private&q=hello"))


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        Fixture.hits = []

    def scan(self, path="/?q=apple", **options):
        return assess(self.base + path, {**OPTIONS, **options}, lab_origins=(self.base,))

    def test_real_http_discovery_and_differential_probes(self):
        r = self.scan()
        self.assertEqual(r["status"], "completed")
        findings = {f["check"]: f for f in r["findings"]}
        self.assertEqual(findings["sql_error"]["verdict"], "suspected")
        self.assertEqual(findings["reflection"]["verdict"], "inconclusive")
        self.assertEqual(findings["content-security-policy"]["verdict"], "confirmed")
        self.assertTrue(any("baseline" in f["evidence"] for f in r["findings"]))
        self.assertNotIn("secret-value", json.dumps(r))
        self.assertNotIn("/delete", Fixture.hits)
        self.assertNotIn("/submit", Fixture.hits)

    def test_passive_does_not_mutate_queries(self):
        r = self.scan(mode="passive")
        self.assertEqual(r["coverage"]["query_parameters_probed"], 0)
        self.assertFalse(any("autoshield_" in path or "%27" in path for path in Fixture.hits))

    def test_budget_stops_scan(self):
        r = self.scan(max_requests=1)
        self.assertEqual(r["status"], "partial")
        self.assertEqual(r["requests_sent"], 1)

    def test_redirect_stays_in_scope(self):
        r = self.scan("/redirect", mode="passive")
        self.assertEqual(r["requests_sent"], 1)
        self.assertIn("redirect_skipped", r["pages"][0])

    def test_response_body_limit(self):
        r = self.scan("/large", max_pages=1, mode="passive")
        self.assertTrue(r["pages"][0]["body_truncated"])

    def test_cancel_before_first_request(self):
        r = assess(self.base, OPTIONS, cancelled=lambda: True, lab_origins=(self.base,))
        self.assertEqual(r["status"], "cancelled")
        self.assertEqual(r["requests_sent"], 0)

    def test_api_lifecycle_and_report(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        import scan_api
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            "AUTOSHIELD_DB_PATH": temp + "/test.db", "AUTOSHIELD_LAB_ORIGINS": self.base,
            "GEMINI_API_KEY": "", "GEMINI_MODEL": "",
        }):
            scan_api.initialize()
            app = FastAPI()
            app.include_router(scan_api.router)
            with TestClient(app) as client:
                self.assertEqual(client.post("/scans", json={"target": self.base, "max_requests": 10001}).status_code, 422)
                response = client.post("/scans", json={"target": self.base + "/slow?q=apple", "max_pages": 2, "mode": "active", "authorization_confirmed": True})
                self.assertEqual(response.status_code, 202)
                scan_id = response.json()["id"]
                self.assertEqual(client.post("/scans", json={"target": self.base, "authorization_confirmed": True}).status_code, 409)
                self.assertEqual(client.post(f"/scans/{scan_id}/cancel").status_code, 200)
                for _ in range(100):
                    scan = client.get(f"/scans/{scan_id}").json()
                    if scan["status"] not in ("queued", "running"):
                        break
                    time.sleep(0.02)
                self.assertEqual(scan["status"], "cancelled")
                self.assertEqual(client.get(f"/scans/{scan_id}/report").status_code, 200)
                self.assertEqual(client.get("/scans/99999").status_code, 404)
                review = client.post(f"/scans/{scan_id}/ai-review").json()
                self.assertEqual(review["status"], "unavailable")
                scan_api.scan_lock.acquire(timeout=5)
                scan_api.scan_lock.release()


class StorageTests(unittest.TestCase):
    def test_restart_and_recovery(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"AUTOSHIELD_DB_PATH": temp + "/test.db"}):
            scan_store.initialize()
            ident = scan_store.create("https://example.com/", OPTIONS)
            scan_store.initialize()
            self.assertEqual(scan_store.get(ident)["status"], "interrupted")
            self.assertEqual(len(scan_store.history()), 1)


if __name__ == "__main__":
    unittest.main()
