import hashlib
import json
from contextlib import closing
from proposals import connect_db

COMPILER_VERSION = "0.1.0"

# Only these trusted patterns can become executable rules.
TEMPLATES = {
    "search_union_select_v1": r"(?i)\bunion\s+(?:all\s+)?select\b",
    "search_numeric_tautology_v1": r"(?i)\bor\s+(\d{1,10})\s*=\s*\1(?![\w.])",
    "search_quoted_tautology_v1": r"(?i)\bor\s+'([^'\r\n]{1,40})'\s*=\s*'\1'",
}
ALLOWED_SCOPE = {"method": "GET", "path": "/rest/products/search", "parameter": "q"}


def compile_proposal(proposal_id):
    if type(proposal_id) is not int or not 1 <= proposal_id <= 100000:
        raise ValueError("Proposal ID is outside the supported range")
    with closing(connect_db()) as db:
        row = db.execute("SELECT * FROM proposals WHERE id = ?", (proposal_id,)).fetchone()
    if row is None:
        raise LookupError("Proposal not found")
    policy = json.loads(row["policy"])
    if not isinstance(policy, dict) or policy.get("schema_version") != "1.0":
        raise ValueError("Unsupported policy schema")
    if policy.get("source") != "trusted_template":
        raise ValueError("Unsupported proposal source")
    if policy.get("attack_type") != "SQL injection":
        raise ValueError("Unsupported attack type")
    if policy.get("scope") != ALLOWED_SCOPE:
        raise ValueError("Proposal scope is not allowed")
    if policy.get("proposed_action") != "deny" or policy.get("proposed_http_status") != 403:
        raise ValueError("Unsupported enforcement action")
    template_ids = policy.get("template_ids")
    if (not isinstance(template_ids, list) or not 1 <= len(template_ids) <= 3
            or any(not isinstance(item, str) or item not in TEMPLATES for item in template_ids)):
        raise ValueError("Unsupported template selection")
    if len(template_ids) != len(set(template_ids)):
        raise ValueError("Duplicate template IDs")
    lines = [
        "# AutoShield candidate rule bundle",
        f"# Proposal ID: {proposal_id}",
        f"# Compiler version: {COMPILER_VERSION}",
        "# Not validated or deployed", "",
    ]
    rule_ids = []
    for index, template_id in enumerate(sorted(template_ids), start=1):
        rule_id = 1100000 + proposal_id * 10 + index
        rule_ids.append(rule_id)
        pattern = TEMPLATES[template_id]
        # AI review text is never read or interpolated by this compiler.
        lines.extend([
            (
                'SecRule REQUEST_METHOD "@streq GET" '
                f'"id:{rule_id},phase:2,deny,status:403,log,'
                f"msg:'AutoShield candidate {proposal_id}',"
                f"tag:'autoshield/candidate/{proposal_id}',"
                't:none,chain"'
            ),
            ('    SecRule REQUEST_FILENAME '
             '"@streq /rest/products/search" '
             '"t:none,chain"'),
            (f'        SecRule ARGS_GET:q "@rx {pattern}" '
             '"t:none,t:replaceComments"'),
            "",
        ])
    content = "\n".join(lines) + "\n"
    return {
        "proposal_id": proposal_id, "compiler_version": COMPILER_VERSION,
        "compile_status": "compiled", "validation_status": "not_run",
        "deployment_status": "not_deployed", "rule_ids": rule_ids,
        "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "content": content,
    }
