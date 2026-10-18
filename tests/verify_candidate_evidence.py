import hashlib
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)


RULE_PATH = (
    "/etc/modsecurity.d/owasp-crs/rules/"
    "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = build_opener(
    ProxyHandler({}),
    NoRedirects(),
)


def command(*args):
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(args)}\n"
            f"{result.stdout}\n{result.stderr}"
        )

    return result.stdout, result.stderr


def read_rule_hash(container_id):
    output, _ = command(
        "docker", "exec", container_id,
        "sha256sum", RULE_PATH,
    )
    return output.split()[0].lower()


def run(proposal_id):
    with OPENER.open(
        f"http://127.0.0.1:8010/proposals/{proposal_id}/compiled",
        timeout=10,
    ) as response:
        compiled = json.load(response)

    expected_hash = compiled["sha256"]
    content_hash = hashlib.sha256(
        compiled["content"].encode("utf-8")
    ).hexdigest()

    if content_hash != expected_hash:
        raise RuntimeError("Compiler content and returned hash disagree")

    expected_ids = {str(value) for value in compiled["rule_ids"]}

    output, _ = command(
        "docker", "compose", "ps", "-q", "candidate-waf"
    )
    container_id = output.strip()

    if not container_id:
        raise RuntimeError("Candidate WAF is not running")

    output, _ = command("docker", "inspect", container_id)
    container_info = json.loads(output)[0]

    before_hash = read_rule_hash(container_id)

    if before_hash != expected_hash:
        raise RuntimeError(
            "Candidate rule file does not match this proposal.\n"
            f"Expected: {expected_hash}\n"
            f"Found:    {before_hash}"
        )

    syntax_stdout, syntax_stderr = command(
        "docker", "exec", container_id, "nginx", "-t"
    )

    started_at = datetime.now(timezone.utc).isoformat()
    probe_id = uuid.uuid4().hex

    query = urlencode({
        "q": "' OR 1=1--",
        "_autoshield_probe": probe_id,
    })

    request = Request(
        f"http://127.0.0.1:8082/rest/products/search?{query}",
        headers={
            "User-Agent": "AutoShield-Evidence-Probe/0.1",
            "Accept": "application/json",
        },
    )

    try:
        with OPENER.open(request, timeout=10) as response:
            http_status = response.status
    except HTTPError as exc:
        http_status = exc.code
        exc.close()

    stdout, stderr = command(
        "docker", "logs",
        "--since", started_at,
        container_id,
    )

    matching_transactions = []

    for line in (stdout + "\n" + stderr).splitlines():
        try:
            audit = json.loads(line)
        except ValueError:
            continue

        if not isinstance(audit, dict):
            continue

        transaction = audit.get("transaction", {})
        uri = transaction.get("request", {}).get("uri", "")
        parameters = parse_qs(urlsplit(uri).query)

        if parameters.get("_autoshield_probe") != [probe_id]:
            continue

        matched_ids = {
            str(message.get("details", {}).get("ruleId"))
            for message in transaction.get("messages", [])
        }

        matching_transactions.append({
            "transaction_id": transaction.get("unique_id"),
            "http_status": transaction.get("response", {}).get("http_code"),
            "interrupted": transaction.get("is_interrupted"),
            "matched_rule_ids": sorted(matched_ids),
            "matched_candidate_rule_ids": sorted(
                matched_ids & expected_ids
            ),
        })

    after_hash = read_rule_hash(container_id)

    attributed = any(
        item["http_status"] == 403
        and item["interrupted"] is True
        and item["matched_candidate_rule_ids"]
        for item in matching_transactions
    )

    verified = (
        http_status == 403
        and before_hash == after_hash == expected_hash
        and attributed
    )

    report = {
        "proposal_id": proposal_id,
        "probe_id": probe_id,
        "checked_at": started_at,
        "container_id": container_id,
        "container_image_id": container_info["Image"],
        "expected_compiled_sha256": expected_hash,
        "rule_file_sha256_before": before_hash,
        "rule_file_sha256_after": after_hash,
        "syntax_check": "passed",
        "syntax_output": (syntax_stdout + syntax_stderr).strip(),
        "probe_http_status": http_status,
        "audit_transactions": matching_transactions,
        "candidate_match_verified": bool(verified),
        "scope": "Rule-file integrity and one numeric SQLi probe",
        "full_validation_complete": False,
    }

    print(json.dumps(report, indent=2))

    if not verified:
        print(
            "\nEvidence check incomplete or failed. "
            "Inspect the candidate WAF logs.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    try:
        selected_proposal = int(sys.argv[1]) if len(sys.argv) > 1 else 1
        sys.exit(run(selected_proposal))
    except Exception as exc:
        print(f"Evidence check failed: {exc}", file=sys.stderr)
        sys.exit(1)