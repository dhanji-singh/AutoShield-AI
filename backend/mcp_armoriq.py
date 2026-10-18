"""ArmorIQ 0.6.7 session adapter. No simulated cloud decisions."""
import os
from mcp_policy import trusted_plan

class ArmorGate:
    def __init__(self, run_id):
        self.client = self.session = self.token = None
        self.state = "disabled"
        mode = os.getenv("MCP_ARMORIQ_MODE", "required").strip().lower()
        if mode == "disabled":
            return
        key = os.getenv("ARMORIQ_API_KEY", "").strip()
        if mode != "required" or not key:
            self.state = "unavailable"
            return
        try:
            from armoriq_sdk import ArmorIQClient, SessionOptions
            self.client = ArmorIQClient(api_key=key,
                agent_id="autoshield-lab-agent", user_id="local-lab-operator", context_id=run_id,
                timeout=8, max_retries=0)
            self.session = self.client.start_session(SessionOptions(mode="sdk", validity_seconds=300))
            self.token = self.session.start_plan(trusted_plan(),
                goal="Inspect synthetic lab health using only operator-defined read-only capabilities. Never read secrets, modify data or execute arbitrary commands.")
            self.state = "plan_created"
        except Exception:
            # Provider exception strings may contain credentials or raw payloads.
            self.state = "unavailable"
            self.close()
    def check(self, tool, args):
        if self.state == "disabled":
            return True, {"status": "disabled", "reason": "Local policy only; ArmorIQ not connected"}
        if self.state == "unavailable":
            return False, {"status": "unavailable", "reason": "ArmorIQ required but unavailable; execution denied"}
        try:
            result = self.session.check("autoshield__" + tool, args)
            raw_action = getattr(result.action, "value", result.action)
            action = raw_action if raw_action in ("allow", "block", "hold") else "invalid"
            allowed = result.allowed is True and action == "allow"
            return allowed, {"status": action, "reason": "ArmorIQ enforcement: " + action}
        except Exception:
            return False, {"status": "unavailable", "reason": "ArmorIQ enforcement failed; execution denied"}
    def report(self, tool, args, result, success):
        if self.session and self.token:
            try:
                from armoriq_sdk import ReportOptions
                self.session.report("autoshield__" + tool, args, result,
                    ReportOptions(status="success" if success else "failed"))
                return "submitted_unconfirmed"
            except Exception:
                return "failed"
        return "not_submitted"
    def close(self):
        state = "not_applicable"
        client, session, token = self.client, self.session, self.token
        self.client = self.session = self.token = None
        self.state = "unavailable"
        if client and token:
            try:
                client.complete_plan(token.plan_id)
                state = "completed"
            except Exception:
                state = "completion_failed"
        if session:
            try:
                session.close()
            except Exception:
                pass
        return state
