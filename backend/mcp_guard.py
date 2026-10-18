"""Single execution boundary shared by every exported MCP tool."""
import threading
import uuid
from mcp_policy import evaluate, fingerprint
from mcp_executor import execute
from mcp_ai import semantic_check
from mcp_armoriq import ArmorGate

class Guard:
    def __init__(self, audit, executor=execute, armor_factory=ArmorGate, semantic=semantic_check):
        self.audit, self.executor, self.armor_factory, self.semantic = audit, executor, armor_factory, semantic
        self.lock = threading.Lock()
    def open_run(self, run_id, source):
        armor = self.armor_factory(run_id)
        return {"id": run_id, "source": source, "armor": armor, "calls": 0}
    def invoke(self, run, tool, args):
        # Serial execution and per-run budget prevent racing policy mutations.
        with self.lock:
            run["calls"] += 1
            call_id = uuid.uuid4().hex
            digest = fingerprint(tool, args)
            decision, effective, reason = evaluate(tool, args)
            if run["calls"] > 8:
                decision, reason = "BLOCK", "Run tool budget exhausted"
            cached = self.audit.denied(digest)
            if cached:
                decision, reason = "BLOCK", "Exact request fingerprint previously denied"
            armor_result = {"status": "not_consulted", "reason": "Remote enforcement not reached"}
            semantic_status = "not_consulted"
            local_decision = decision
            if decision != "BLOCK":
                safe, semantic_status = self.semantic(tool, effective)
                if not safe:
                    decision, reason = "BLOCK", "Semantic guard denied or unavailable"
                else:
                    safe, armor_result = run["armor"].check(tool, effective)
                    if not safe:
                        decision, reason = "BLOCK", armor_result["reason"]
            base = {"run_id": run["id"], "call_id": call_id, "source": run["source"],
                    "agent": "autoshield-lab-agent", "tool": tool, "fingerprint": digest,
                    "decision": decision, "local_decision": local_decision, "reason": reason,
                    "semantic": semantic_status, "armoriq": armor_result,
                    "effective_fingerprint": fingerprint(tool, effective) if effective else None}
            # No raw denied payloads retained. Canonical allowed arguments contain only fixed lab data.
            if decision != "BLOCK":
                base["effective_arguments"] = effective
            self.audit.emit(stage="decision", executed=False, **base)
            if decision == "BLOCK":
                # Persist only local deterministic denials. Provider outages must not become permanent policy.
                if local_decision == "BLOCK" and run["calls"] <= 8 and not cached and self.audit.tighten(digest):
                    self.audit.emit(stage="policy_tightened", run_id=run["id"], call_id=call_id,
                        diff={"before": "exact request has no cached deny", "after": "deny sha256:" + digest},
                        reason="Exact-match deny cache added; capabilities were not expanded")
                return {"decision": "BLOCK", "executed": False, "reason": reason, "call_id": call_id}
            try:
                result = self.executor(tool, effective)
                success = True
            except Exception:
                result = {"error": "Lab operation failed; inspect lab service availability"}
                success = False
            self.audit.emit(stage="result", executed=True, success=success, result=result, **base)
            report_status = run["armor"].report(tool, effective, result, success)
            if report_status != "not_submitted":
                self.audit.emit(stage="armoriq_report", run_id=run["id"], call_id=call_id, status=report_status)
            return {"decision": decision, "executed": True, "success": success, "result": result, "call_id": call_id}
