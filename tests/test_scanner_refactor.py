"""Regression coverage for limits, real TLS, identity, and OWASP heuristics."""

import json
import os
from pathlib import Path
import ssl
import ipaddress
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from scan_engine import assess, canonical_url, ScopeError
from scan_identity import deduplicate_findings, finding_fingerprint
from scan_checks import RESPONSE_CHECKS
from scan_api import ScanRequest

OPTIONS = dict(
    mode="passive",
    max_pages=200,
    max_requests=300,
    max_depth=2,
    delay_seconds=0,
    max_seconds=30,
)


class Site(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (
            "".join(f'<a href="/page/{n}">{n}</a>' for n in range(45))
            if self.path == "/"
            else "ok"
        )
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class RefactorTests(unittest.TestCase):
    def test_settings(self):
        with patch.dict(
            os.environ, {"SCANNER_MAX_PAGES": "250", "SCANNER_VERIFY_SSL": "false"}
        ):
            self.assertEqual(ScanRequest(target="example.test").max_pages, 250)
            self.assertFalse(ScanRequest(target="example.test").verify_ssl)
            self.assertEqual(
                ScanRequest(target="example.test", max_pages=12).max_pages, 12
            )
            self.assertIsNone(
                ScanRequest(target="example.test", max_pages=None).max_pages
            )
            self.assertEqual(
                ScanRequest(target="example.test", max_pages=0).max_pages, 0
            )
        for value in (-1, True, 1.5):
            with self.assertRaises(ValueError):
                ScanRequest(target="example.test", max_pages=value)

    def test_scheme(self):
        self.assertEqual(
            canonical_url("EXAMPLE.test:443/a#fragment"), "https://example.test/a"
        )
        self.assertEqual(canonical_url("//example.test"), "https://example.test/")
        for value in (
            "javascript:alert(1)",
            "ftp://example.test",
            "https://u:p@example.test",
        ):
            with self.assertRaises(ValueError):
                canonical_url(value)

    def test_crawl_beyond_30_and_unlimited(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            for limit, expected in ((200, 46), (0, 46), (None, 46), (5, 5)):
                r = assess(base, {**OPTIONS, "max_pages": limit}, lab_origins=(base,))
                self.assertEqual(len(r["pages"]), expected)
                self.assertEqual(
                    len({f["fingerprint"] for f in r["findings"]}), len(r["findings"])
                )
            r = assess(
                base,
                {**OPTIONS, "max_pages": 0, "max_requests": 3},
                lab_origins=(base,),
            )
            self.assertEqual(r["stop_reason"], "request budget reached")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_real_self_signed_tls(self):
        with tempfile.TemporaryDirectory() as tmp:
            key, cert = tmp + "/key.pem", tmp + "/cert.pem"
            # Python-generated ephemeral localhost certificate: no OpenSSL CLI or
            # Git Bash path rewriting is required on Windows.
            private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
            now = datetime.now(timezone.utc)
            certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(private.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                .sign(private, hashes.SHA256()))
            Path(key).write_bytes(private.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            Path(cert).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"https://127.0.0.1:{server.server_port}"
            try:
                r = assess(base, {**OPTIONS, "max_pages": 1}, lab_origins=(base,))
                self.assertEqual(r["status"], "failed")
                self.assertIn(
                    "certificate verification failed", r["errors"][0]["error"]
                )
                r = assess(
                    base,
                    {**OPTIONS, "max_pages": 1, "verify_ssl": False},
                    lab_origins=(base,),
                )
                self.assertEqual(len(r["pages"]), 1)
                self.assertFalse(r["coverage"]["verify_ssl"])
                with patch.dict(os.environ, {"SSL_CERT_FILE": cert}):
                    r = assess(
                        base,
                        {**OPTIONS, "max_pages": 1, "verify_ssl": True},
                        lab_origins=(base,),
                    )
                    self.assertEqual(len(r["pages"]), 1)
                with self.assertRaises(ScopeError):
                    assess("https://example.test", {**OPTIONS, "verify_ssl": False})
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_identity(self):
        def f(url, method="GET", parameter="q"):
            return {
                "check": "reflection",
                "evidence": {
                    "url": "https://example.test/?q=random",
                    "baseline": {"url": url},
                    "method": method,
                    "parameter": parameter,
                },
            }

        first = f("https://EXAMPLE.test:443/%7Euser?b=2&q=apple#part")
        second = f("https://example.test/~user?q=apple&b=2")
        self.assertEqual(finding_fingerprint(first), finding_fingerprint(second))
        self.assertEqual(len(deduplicate_findings([first, second])), 1)
        for other in (
            f("https://example.test/other"),
            f("https://example.test/~user?q=apple&b=2", "POST"),
            f("https://example.test/~user?q=apple&b=2", parameter="b"),
        ):
            self.assertNotEqual(finding_fingerprint(first), finding_fingerprint(other))

    def test_owasp_checks_no_secret_values(self):
        r = {
            "url": "https://example.test/admin/access.log?file=../data",
            "status": 200,
            "headers": [("WWW-Authenticate", 'Basic realm="test"')],
            "body": '<title>Index of /</title>\nroot:x:0:0:root\nTraceback (most recent call last):\nINFO log entry\n{"api_key":"SECRET_DO_NOT_RETAIN"}',
        }
        observations = []

        def add(check, title, severity, verdict, why, response, fix, **details):
            observations.append({"check": check, **details})

        for check in RESPONSE_CHECKS:
            check(r, {"content-type": "text/html"}, add)
        checks = {f["check"] for f in observations}
        self.assertTrue(
            {
                "directory_listing",
                "system_file_exposure",
                "traversal_input",
                "basic_auth",
                "authentication_surface",
                "stack_trace",
                "public_log",
                "sensitive_response_credential_assignment",
                "hsts",
                "x-frame-options",
            }
            <= checks
        )
        self.assertNotIn("SECRET_DO_NOT_RETAIN", json.dumps(observations))
        observations.clear()
        for check in RESPONSE_CHECKS:
            check(
                {**r, "body": "Welcome", "url": "https://example.test/", "headers": []},
                {
                    "content-type": "text/html",
                    "content-security-policy": "frame-ancestors 'none'",
                    "x-content-type-options": "nosniff",
                    "strict-transport-security": "max-age=3600",
                },
                add,
            )
        self.assertEqual(observations, [])


class ExportTests(unittest.TestCase):
    def test_saved_json_and_html_deduplicate(self):
        import scan_store
        from scan_report import render_html

        finding = {
            "id": 1,
            "check": "example",
            "title": "Unique observation",
            "evidence": {"url": "https://example.test/", "method": "GET"},
        }
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"AUTOSHIELD_DB_PATH": tmp + "/scans.db"}
        ):
            scan_store.initialize()
            ident = scan_store.create("https://example.test/", OPTIONS)
            report = {
                "status": "completed",
                "findings": [finding, {**finding, "id": 2}],
            }
            scan_store.save(ident, report, final=True)
            self.assertEqual(len(scan_store.get(ident)["report"]["findings"]), 1)
            self.assertEqual(
                render_html({"report": {"findings": [finding, finding]}}).count(
                    "Unique observation"
                ),
                1,
            )

    def test_fingerprint_stable_across_probe_markers(self):
        from scan_compare import group_findings

        a = {
            "check": "reflection",
            "evidence": {
                "url": "https://example.test/?q=marker1",
                "baseline": {"url": "https://example.test/?q=apple"},
                "parameter": "q",
            },
        }
        b = {
            **a,
            "evidence": {**a["evidence"], "url": "https://example.test/?q=marker2"},
        }
        groups = group_findings({"report": {"findings": [a, b]}})
        self.assertEqual(len(groups), 1)
        self.assertEqual(
            next(iter(groups.values()))["fingerprint"], finding_fingerprint(a)
        )
