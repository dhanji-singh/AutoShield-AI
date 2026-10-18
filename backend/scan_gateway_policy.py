"""Real ArmorIQ decisions for one concrete scanner request. No local allow mode."""

import hashlib
import json
import logging
import os

TOOL = "autoshield_scanner__http_get"


class ScannerArmor:
    def evaluate(self, arguments):
        key = os.getenv("ARMORIQ_API_KEY", "").strip()
        if not key:
            return False, {
                "attribution": "ArmorIQ",
                "action": "BLOCK",
                "reason": "ARMORIQ_KEY_MISSING",
            }
        self.session = self.client = self.token = None
        session = client = token = None
        try:
            from armoriq_sdk import ArmorIQClient, SessionOptions

            logging.getLogger("armoriq_sdk").setLevel(logging.CRITICAL)
            client = ArmorIQClient(
                api_key=key,
                user_id="local-scan-operator",
                agent_id="autoshield-scanner",
                timeout=8,
                max_retries=0,
            )
            self.client = client
            session = client.start_session(
                SessionOptions(
                    mode="sdk",
                    default_mcp_name="autoshield_scanner",
                    validity_seconds=120,
                )
            )
            # Discovered URLs are unknown at scan start. Capture each exact request,
            # then ask cloud policy; plan capture itself never authorizes execution.
            self.session = session
            token = session.start_plan(
                [{"name": TOOL, "args": arguments}],
                goal="Evaluate one operator-requested HTTP GET security assessment request",
            )
            self.token = token
            self.arguments = arguments
            decision = session.check(TOOL, arguments)
            action = getattr(decision.action, "value", decision.action)
            allowed = decision.allowed is True and action == "allow"
            raw_reason = str(getattr(decision, "reason", "") or "")
            # Never persist arbitrary provider messages or response bodies.
            reason = (
                raw_reason
                if raw_reason
                in (
                    "no_matching_policy",
                    "policy_denied",
                    "plan_deviation",
                    "policy_hold",
                )
                else "ARMORIQ_" + ("ALLOW" if allowed else "DENIED_OR_HELD")
            )
            return allowed, {
                "attribution": "ArmorIQ",
                "action": "ALLOW" if allowed else "BLOCK",
                "reason": reason,
                "cloud_action": (
                    action if action in ("allow", "block", "hold") else "unsupported"
                ),
                "argument_hash": hashlib.sha256(
                    json.dumps(arguments, sort_keys=True).encode()
                ).hexdigest(),
            }
        except Exception:
            return False, {
                "attribution": "ArmorIQ",
                "action": "BLOCK",
                "reason": "ARMORIQ_UNAVAILABLE",
            }

    def finish(self, success=False, result_hash=None):
        session, client, token = (
            getattr(self, k, None) for k in ("session", "client", "token")
        )
        try:
            if session and token and result_hash:
                from armoriq_sdk import ReportOptions

                session.report(
                    TOOL,
                    self.arguments,
                    {"success": success, "body_sha256": result_hash},
                    ReportOptions(status="success" if success else "failed"),
                )
        except Exception:
            pass
        try:
            if client and token:
                client.complete_plan(token.plan_id)
        except Exception:
            pass
        try:
            if session:
                session.close()
        except Exception:
            pass
        self.session = self.client = self.token = None
