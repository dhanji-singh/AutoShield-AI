"""Gateway unit tests plus real MCP subprocess fail-closed smoke test."""

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from scan_mcp_server import ScannerGateway
from scan_mcp_client import MCPScanTransport, GatewayBlocked
from scan_gateway_policy import ScannerArmor, TOOL
from scan_engine import assess, ScopeError, StopScan

OPTIONS = dict(
    mode="passive",
    max_requests=20,
    delay_seconds=0,
    max_seconds=30,
    verify_ssl=True,
    max_pages=1,
    max_depth=0,
)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = {
            **OPTIONS,
            "target": "https://example.com/",
            "lab_origins": [],
            "cancel_file": self.tmp.name + "/cancel",
        }
        self.armor = Mock()
        self.armor.evaluate.return_value = (
            True,
            {"attribution": "ArmorIQ", "action": "ALLOW", "reason": "ARMORIQ_ALLOW"},
        )
        self.gate = ScannerGateway(self.config, self.armor)
        self.gate.transport.fetch = Mock(
            return_value={"url": "https://example.com/", "body_sha256": "hash"}
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_allow_executes_and_reports(self):
        self.assertEqual(
            self.gate.fetch("https://example.com/", "page_fetch")["decision"], "ALLOW"
        )
        self.gate.transport.fetch.assert_called_once()
        self.armor.finish.assert_called_once_with(success=True, result_hash="hash")

    def test_deny_never_fetches(self):
        self.armor.evaluate.return_value = (
            False,
            {"action": "BLOCK", "reason": "policy_denied"},
        )
        self.assertEqual(
            self.gate.fetch("https://example.com/", "page_fetch")["decision"], "BLOCK"
        )
        self.gate.transport.fetch.assert_not_called()

    def test_hold_does_not_become_allow(self):
        import armoriq_sdk

        client = Mock()
        session = client.start_session.return_value
        session.check.return_value = Mock(
            allowed=True, action="hold", reason="policy_hold"
        )
        with patch.dict(os.environ, {"ARMORIQ_API_KEY": "fake-test-key"}), patch.object(
            armoriq_sdk, "ArmorIQClient", return_value=client
        ):
            armor = ScannerArmor()
            self.assertFalse(armor.evaluate({"url": "https://example.com/"})[0])
            armor.finish()
            session.report.assert_not_called()
            self.assertEqual(session.check.call_args.args[0], TOOL)

    def test_scope_and_passive_mode(self):
        for url, purpose in [
            ("https://other.example/", "page_fetch"),
            ("https://example.com/", "sql_error"),
        ]:
            self.assertEqual(self.gate.fetch(url, purpose)["decision"], "BLOCK")
        self.gate.transport.fetch.assert_not_called()
        self.armor.evaluate.assert_not_called()

    def test_cancel_after_cloud_check(self):
        def allow(args):
            Path(self.config["cancel_file"]).touch()
            return True, {"action": "ALLOW"}

        self.armor.evaluate.side_effect = allow
        self.assertEqual(
            self.gate.fetch("https://example.com/", "page_fetch")["decision"], "STOP"
        )
        self.gate.transport.fetch.assert_not_called()

    def test_budget_before_cloud(self):
        self.gate.transport.count = 20
        self.assertEqual(
            self.gate.fetch("https://example.com/", "page_fetch")["decision"], "STOP"
        )
        self.armor.evaluate.assert_not_called()

    def test_real_mcp_missing_key_no_network(self):
        with patch.dict(os.environ, {"ARMORIQ_API_KEY": ""}):
            with MCPScanTransport(
                "https://example.com/", OPTIONS, (), lambda: False
            ) as transport:
                with self.assertRaises(GatewayBlocked) as result:
                    transport.fetch("https://example.com/")
                self.assertEqual(
                    result.exception.policy["reason"], "ARMORIQ_KEY_MISSING"
                )
                self.assertEqual(transport.count, 0)
            self.assertFalse(transport.thread.is_alive())

    def test_real_mcp_denial_in_scan_report(self):
        with patch.dict(os.environ, {"ARMORIQ_API_KEY": ""}):
            with MCPScanTransport(
                "https://example.com/", OPTIONS, (), lambda: False
            ) as transport:
                report = assess(
                    "https://example.com/",
                    OPTIONS,
                    transport_factory=lambda *args: transport,
                )
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["requests_sent"], 0)
        self.assertEqual(report["check_runs"][0]["status"], "blocked")
        self.assertEqual(
            report["errors"][0]["gateway"]["reason"], "ARMORIQ_KEY_MISSING"
        )


class PublicNetworkTests(unittest.TestCase):
    def test_cloud_allow_cannot_reach_private_dns_answer(self):
        import socket

        with tempfile.TemporaryDirectory() as tmp:
            armor = Mock()
            armor.evaluate.return_value = (True, {"action": "ALLOW"})
            gate = ScannerGateway(
                {
                    **OPTIONS,
                    "target": "https://example.com/",
                    "lab_origins": [],
                    "cancel_file": tmp + "/cancel",
                },
                armor,
            )
            answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
            with patch("scan_engine.socket.getaddrinfo", return_value=answers), patch(
                "scan_engine.socket.create_connection"
            ) as connect:
                result = gate.fetch("https://example.com/", "page_fetch")
            self.assertEqual(result["decision"], "BLOCK")
            self.assertEqual(result["requests_sent"], 0)
            connect.assert_not_called()


class ProtocolExecutionTests(unittest.TestCase):
    def test_real_stdio_and_http_with_test_only_cloud_stub(self):
        # Only the cloud decision is stubbed in this temporary test harness.
        # Production has no test-allow environment variable or fallback route.
        import asyncio
        import json
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        hits = []

        class Site(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"actual local fixture")

            def log_message(self, *a):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                script = Path(tmp) / "fixture_server.py"
                backend = str(Path(__file__).resolve().parents[1] / "backend")
                script.write_text(
                    "import sys\nsys.path.insert(0,"
                    + repr(backend)
                    + ')\nimport scan_mcp_server as server\nclass TestArmor:\n def evaluate(self,args):\n  allow=not args["url"].endswith("/denied")\n  return allow,{"action":"ALLOW" if allow else "BLOCK","reason":"TEST_ONLY_CLOUD_STUB"}\n def finish(self,**kwargs):pass\nserver.ScannerArmor=TestArmor\nserver.main()\n'
                )
                env = dict(os.environ)
                env.pop("ARMORIQ_API_KEY", None)
                env["AUTOSHIELD_SCAN_CONFIG"] = json.dumps(
                    {
                        **OPTIONS,
                        "target": base,
                        "lab_origins": [base],
                        "cancel_file": tmp + "/cancel",
                    }
                )

                async def run():
                    with open(os.devnull, "w") as errors:
                        async with stdio_client(
                            StdioServerParameters(
                                command=sys.executable, args=[str(script)], env=env
                            ),
                            errlog=errors,
                        ) as (read, write):
                            async with ClientSession(read, write) as session:
                                await session.initialize()
                                self.assertIn(
                                    "http_get",
                                    {
                                        t.name
                                        for t in (await session.list_tools()).tools
                                    },
                                )
                                allowed = await session.call_tool(
                                    "http_get",
                                    {"url": base + "/", "purpose": "page_fetch"},
                                )
                                denied = await session.call_tool(
                                    "http_get",
                                    {"url": base + "/denied", "purpose": "page_fetch"},
                                )
                                self.assertEqual(
                                    (allowed.structuredContent or json.loads(allowed.content[0].text))["response"]["body"],
                                    "actual local fixture",
                                )
                                self.assertEqual(
                                    (denied.structuredContent or json.loads(denied.content[0].text))["decision"], "BLOCK"
                                )

                asyncio.run(run())
                self.assertEqual(hits, ["/"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
