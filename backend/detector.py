import re
from urllib.parse import unquote_plus


DETECTOR_VERSION = "0.1.0"

PATTERNS = [
    (
        "SQLI-001",
        re.compile(
            r"\bunion\s+(?:all\s+)?select\b",
            re.IGNORECASE,
        ),
        "UNION SELECT sequence found",
    ),
    (
        "SQLI-002",
        re.compile(
            r"\bor\s+(\d{1,10})\s*=\s*\1(?![\w.])",
            re.IGNORECASE,
        ),
        "OR condition compares the same numeric value",
    ),
    (
        "SQLI-003",
        re.compile(
            r"\bor\s+'([^'\r\n]{1,40})'\s*=\s*'\1'",
            re.IGNORECASE,
        ),
        "OR condition compares the same quoted value",
    ),
]


def classify_event(event):
    result = {
        "detector_version": DETECTOR_VERSION,
        "status": "not_evaluated",
        "attack_type": None,
        "matched_rules": [],
        "reasons": [],
        "evidence_truncated": bool(event.get("query_truncated", False)),
    }

    if (
        event.get("method") != "GET"
        or event.get("path") != "/rest/products/search"
    ):
        result["reasons"] = ["Outside the current detector scope"]
        return result

    raw = event.get("query_evidence")

    if not isinstance(raw, str):
        result["reasons"] = ["Search evidence was not captured"]
        return result

    # Nginx captures the URL-encoded parameter.
    # Decode once to match normal query-string decoding.
    decoded = unquote_plus(raw[:2048])

    # Normalize SQL block comments into whitespace.
    normalized = re.sub(
        r"/\*.*?\*/",
        " ",
        decoded,
        flags=re.DOTALL,
    )

    for rule_id, pattern, reason in PATTERNS:
        if pattern.search(normalized):
            result["matched_rules"].append(rule_id)
            result["reasons"].append(reason)

    if result["matched_rules"]:
        result["status"] = "suspicious"
        result["attack_type"] = "SQL injection"
    elif result["evidence_truncated"]:
        result["status"] = "inconclusive"
        result["reasons"] = ["Evidence was truncated; no pattern matched"]
    else:
        result["status"] = "no_match"
        result["reasons"] = ["No configured SQLi pattern matched"]

    return result