"""Synchronous crawler bridge to one persistent official MCP stdio connection."""

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import timedelta
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time

from scan_engine import ScopeError, StopScan


class GatewayBlocked(ScopeError):
    def __init__(self, policy):
        self.policy = policy
        super().__init__(policy.get("reason", "MCP_GATEWAY_BLOCKED"))


class MCPScanTransport:
    def __init__(self, target, options, lab_origins, cancelled):
        self.cancelled = cancelled
        self.count = 0
        self.purpose = "page_fetch"
        self.last_policy = None
        self.deadline = time.monotonic() + options["max_seconds"]
        self.tmp = tempfile.TemporaryDirectory(prefix="autoshield-scan-")
        self.cancel_file = Path(self.tmp.name) / "cancel"
        self.config = {
            key: options[key]
            for key in (
                "mode",
                "max_requests",
                "delay_seconds",
                "max_seconds",
                "verify_ssl",
            )
        }
        self.config.update(
            target=target,
            lab_origins=list(lab_origins),
            cancel_file=str(self.cancel_file),
        )
        self.ready = threading.Event()
        self.failed = False
        self.session = self.loop = self.stop = None
        self.thread = threading.Thread(target=self._thread, daemon=True)

    def __enter__(self):
        self.thread.start()
        if not self.ready.wait(15) or self.failed:
            self.close()
            raise GatewayBlocked(
                {
                    "attribution": "MCP",
                    "action": "BLOCK",
                    "reason": "MCP_STARTUP_FAILED",
                }
            )
        return self

    def _thread(self):
        try:
            asyncio.run(self._serve())
        except BaseException:
            self.failed = True
        finally:
            self.ready.set()

    async def _serve(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        self.loop = asyncio.get_running_loop()
        self.stop = asyncio.Event()
        # Explicit inheritance: no Groq/Gemini credentials go to this tool process.
        env = {
            k: v
            for k, v in os.environ.items()
            if k
            in (
                "PATH",
                "SYSTEMROOT",
                "WINDIR",
                "HOME",
                "USERPROFILE",
                "TEMP",
                "TMP",
                "SSL_CERT_FILE",
                "SSL_CERT_DIR",
                "ARMORIQ_API_KEY",
            )
        }
        env["AUTOSHIELD_SCAN_CONFIG"] = json.dumps(self.config)
        server = StdioServerParameters(
            command=sys.executable,
            args=[str(Path(__file__).with_name("scan_mcp_server.py"))],
            env=env,
        )
        with open(os.devnull, "w") as errors:
            async with stdio_client(server, errlog=errors) as (read, write):
                async with ClientSession(
                    read, write, read_timeout_seconds=timedelta(seconds=90)
                ) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    if "http_get" not in {tool.name for tool in tools.tools}:
                        raise RuntimeError("Required tool missing")
                    self.session = session
                    self.ready.set()
                    await self.stop.wait()

    def set_context(self, purpose):
        self.purpose = purpose
        self.last_policy = None

    async def _call(self, url):
        result = await self.session.call_tool(
            "http_get", {"url": url, "purpose": self.purpose}
        )
        if result.isError:
            raise RuntimeError("MCP tool failed")
        data = result.structuredContent
        if data is None:
            data = json.loads(
                next(item.text for item in result.content if item.type == "text")
            )
        return data

    def fetch(self, url):
        if self.failed or self.session is None:
            raise GatewayBlocked(
                {"attribution": "MCP", "action": "BLOCK", "reason": "MCP_UNAVAILABLE"}
            )
        future = asyncio.run_coroutine_threadsafe(self._call(url), self.loop)
        until = time.monotonic() + 90
        while True:
            if self.cancelled() or time.monotonic() >= self.deadline:
                self.cancel_file.touch()
                future.cancel()
                raise StopScan(
                    "cancelled" if self.cancelled() else "time limit reached"
                )
            try:
                result = future.result(timeout=0.1)
                break
            except FutureTimeout:
                if time.monotonic() >= until:
                    self.cancel_file.touch()
                    future.cancel()
                    raise GatewayBlocked(
                        {
                            "attribution": "MCP",
                            "action": "BLOCK",
                            "reason": "MCP_TIMEOUT",
                        }
                    )
            except Exception:
                raise GatewayBlocked(
                    {
                        "attribution": "MCP",
                        "action": "BLOCK",
                        "reason": "MCP_PROTOCOL_FAILED",
                    }
                ) from None
        if (
            not isinstance(result, dict)
            or type(result.get("requests_sent")) is not int
            or result["requests_sent"] < self.count
        ):
            raise GatewayBlocked(
                {
                    "attribution": "MCP",
                    "action": "BLOCK",
                    "reason": "INVALID_GATEWAY_RESULT",
                }
            )
        self.count = result["requests_sent"]
        self.last_policy = result.get("policy")
        decision = result["decision"]
        if decision == "BLOCK":
            raise GatewayBlocked(
                self.last_policy
                or {
                    "attribution": "MCP",
                    "action": "BLOCK",
                    "reason": "MCP_GATEWAY_BLOCKED",
                }
            )
        if decision == "STOP":
            raise StopScan(result["reason"])
        if decision == "ERROR":
            raise ScopeError(result["reason"])
        if (
            decision != "ALLOW"
            or not self.last_policy
            or self.last_policy.get("action") != "ALLOW"
        ):
            raise GatewayBlocked(
                {
                    "attribution": "MCP",
                    "action": "BLOCK",
                    "reason": "INVALID_GATEWAY_RESULT",
                }
            )
        return result["response"]

    def close(self):
        self.cancel_file.touch()
        if self.loop and self.stop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.stop.set)
        self.thread.join(timeout=15)
        if not self.thread.is_alive():
            self.tmp.cleanup()

    def __exit__(self, *args):
        self.close()
