"""Tool-specific capability policy; independent of the HTTP/WAF detector."""
import hashlib
import json
import re

COMMANDS = {"pwd": "pwd", "date -u": "date -u", "df -h /workspace": "df -h /workspace"}
FILES = ("ops.log", "injection.log")
METRICS = ("uptime", "disk")
SQL = "SELECT name, status FROM services LIMIT {}"

def fingerprint(tool, arguments):
    return hashlib.sha256(json.dumps([tool, arguments], sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def evaluate(tool, arguments):
    """Return decision, effective args, reason. Never use model-provided identity."""
    fields = {"read_system_metrics": "metric_name", "read_lab_file": "path",
              "query_database": "sql_query", "run_system_command": "command_str", "invoke_lab_api": "resource"}
    field = fields.get(tool)
    if not field or not isinstance(arguments, dict) or set(arguments) != {field}:
        return "BLOCK", {}, "Unknown tool or unexpected arguments"
    value = arguments[field]
    if not isinstance(value, str) or len(value) > 2048 or "\x00" in value:
        return "BLOCK", {}, "Invalid or oversized argument"
    if tool == "query_database":
        match = re.fullmatch(r"SELECT\s+name\s*,\s*status\s+FROM\s+services(?:\s+LIMIT\s+([0-9]{1,6}))?\s*;?", value.strip(), re.I)
        if not match:
            return "BLOCK", {}, "Only the public services projection is permitted; database writes and secret reads are denied"
        limit = min(int(match[1] or 20), 20)
        if limit < 1:
            return "BLOCK", {}, "LIMIT must be positive"
        effective = {field: SQL.format(limit)}
        if effective != arguments:
            return "SANITIZE", effective, "Canonicalized read-only query; enforced maximum 20 rows"
        return "ALLOW", effective, "Read-only public services projection"
    allowed = {"read_system_metrics": METRICS, "read_lab_file": FILES,
               "run_system_command": COMMANDS, "invoke_lab_api": ("health",)}
    if value not in allowed[tool]:
        return "BLOCK", {}, "Argument is outside the operator-defined capability allowlist"
    return "ALLOW", dict(arguments), "Exact lab capability permitted"

def trusted_plan():
    """Captured before any model response or untrusted log is read."""
    pairs = [("read_system_metrics", "metric_name", x) for x in METRICS]
    pairs += [("read_lab_file", "path", x) for x in FILES]
    pairs += [("run_system_command", "command_str", x) for x in COMMANDS]
    pairs += [("invoke_lab_api", "resource", "health")]
    pairs += [("query_database", "sql_query", SQL.format(n)) for n in range(1, 21)]
    return [{"name": "autoshield__" + tool, "args": {key: value}} for tool, key, value in pairs]
