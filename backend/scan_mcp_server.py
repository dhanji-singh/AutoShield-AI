"""Per-scan official MCP stdio server. Only this process fetches target pages."""

import json
import os
from pathlib import Path
import ssl
import threading

from mcp.server.fastmcp import FastMCP
from scan_engine import Scope, Transport, ScopeError, StopScan
from scan_gateway_policy import ScannerArmor


class ScannerGateway:
    def __init__(self, config, armor=None):
        self.config = config
        self.scope = Scope(config["target"], config["lab_origins"])
        self.transport = Transport(
            self.scope,
            config["max_requests"],
            config["delay_seconds"],
            lambda: Path(config["cancel_file"]).exists(),
            config["max_seconds"],
        )
        self.transport.verify_ssl = config["verify_ssl"]
        self.armor = armor or ScannerArmor()
        self.lock = threading.Lock()

    def fetch(self, url, purpose):
        with self.lock:
            response = None
            try:
                self.transport.check_stop()
                url = self.scope.check(url)
                if not self.transport.verify_ssl and not self.scope.lab:
                    raise ScopeError("TLS verification required for public targets")
                if purpose not in ("page_fetch", "reflection", "sql_error") or (
                    self.config["mode"] == "passive" and purpose != "page_fetch"
                ):
                    raise ScopeError("Probe not permitted in selected scan mode")
                if self.transport.count >= self.transport.budget:
                    raise StopScan("request budget reached")
                arguments = {
                    "url": url,
                    "method": "GET",
                    "mode": self.config["mode"],
                    "purpose": purpose,
                    "origin": self.scope.origin,
                    "verify_ssl": self.transport.verify_ssl,
                }
                allowed, policy = self.armor.evaluate(arguments)
                if not allowed:
                    return {
                        "decision": "BLOCK",
                        "policy": policy,
                        "requests_sent": self.transport.count,
                    }
                # Recheck cancellation/deadline and DNS after cloud decision. Transport
                # pins the validated address; redirects return for separate MCP calls.
                self.transport.check_stop()
                response = self.transport.fetch(url)
                return {
                    "decision": "ALLOW",
                    "policy": policy,
                    "response": response,
                    "requests_sent": self.transport.count,
                }
            except StopScan as exc:
                return {
                    "decision": "STOP",
                    "reason": str(exc),
                    "requests_sent": self.transport.count,
                }
            except ScopeError:
                return {
                    "decision": "BLOCK",
                    "policy": {
                        "attribution": "Scope",
                        "action": "BLOCK",
                        "reason": "SCOPE_OR_ADDRESS_POLICY",
                    },
                    "requests_sent": self.transport.count,
                }
            except ssl.SSLCertVerificationError:
                return {
                    "decision": "ERROR",
                    "reason": "TLS certificate verification failed; configure a trusted CA.",
                    "requests_sent": self.transport.count,
                }
            except ssl.SSLError:
                return {
                    "decision": "ERROR",
                    "reason": "TLS handshake failed.",
                    "requests_sent": self.transport.count,
                }
            except Exception:
                return {
                    "decision": "ERROR",
                    "reason": "Target request failed; check DNS, connectivity and target health.",
                    "requests_sent": self.transport.count,
                }

            finally:
                self.armor.finish(
                    success=response is not None,
                    result_hash=response.get("body_sha256") if response else None,
                )


def main():
    config = json.loads(os.environ["AUTOSHIELD_SCAN_CONFIG"])
    gateway = ScannerGateway(config)
    server = FastMCP("AutoShield Scanner Gateway", log_level="CRITICAL")

    @server.tool()
    def http_get(url: str, purpose: str = "page_fetch") -> dict:
        """Fetch one scoped HTTP(S) page only after an explicit ArmorIQ allow."""
        return gateway.fetch(url, purpose)

    server.run(transport="stdio")


if __name__ == "__main__":
    main()
