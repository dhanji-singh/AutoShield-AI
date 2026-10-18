import json
from contextlib import closing
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from proposals import connect_db
from rule_compiler import compile_proposal


TARGETS = {
    "baseline": "http://staging-waf:8080",
    "candidate": "http://candidate-waf:8080",
}

CASES = [
    ("normal_apple", "apple", 200),
    ("normal_banana", "banana", 200),
    ("normal_multiword", "orange juice", 200),
    ("normal_marker", "autoshield-test-001", 200),
    ("sqli_original", "' OR 1=1--", 403),
    ("sqli_case_variant", "' oR 2=2--", 403),
    ("sqli_comment_variant", "' OR/**/3=3--", 403),
    ("known_apostrophe_issue", "O'Reilly", 200),
]


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def initialize_validations():
    with closing(connect_db()) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS validation_runs (
                id INTEGER PRIMARY KEY,
                proposal_id INTEGER NOT NULL,
                compiled_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                report TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (proposal_id) REFERENCES proposals(id)
            )
        """)
        db.commit()


def request_status(opener, target, query):
    url = (
        f"{TARGETS[target]}/rest/products/search?"
        + urlencode({"q": query})
    )

    request = Request(
        url,
        headers={
            "User-Agent": "AutoShield-Validation/0.1",
            "Accept": "application/json",
        },
    )

    try:
        with opener.open(request, timeout=5) as response:
            return {"http_status": response.status, "error": None}

    except HTTPError as exc:
        code = exc.code
        exc.close()
        return {"http_status": code, "error": None}

    except (URLError, TimeoutError, OSError) as exc:
        return {"http_status": None, "error": str(exc)}


def validate_http(proposal_id):
    compiled = compile_proposal(proposal_id)

    opener = build_opener(
        ProxyHandler({}),
        NoRedirects(),
    )

    started_at = datetime.now(timezone.utc).isoformat()
    results = []

    for name, query, expected in CASES:
        baseline = request_status(opener, "baseline", query)
        candidate = request_status(opener, "candidate", query)

        baseline_code = baseline["http_status"]
        candidate_code = candidate["http_status"]

        if baseline["error"] or candidate["error"]:
            verdict = "error"

        elif (
            name == "known_apostrophe_issue"
            and baseline_code == 500
            and candidate_code == 500
        ):
            verdict = "known_application_issue"

        elif expected == 200:
            verdict = (
                "pass"
                if baseline_code == 200 and candidate_code == 200
                else "fail"
            )

        elif baseline_code not in (200, 403, 500):
            verdict = "inconclusive"

        else:
            verdict = "pass" if candidate_code == expected else "fail"

        results.append({
            "case": name,
            "query": query,
            "expected_candidate_status": expected,
            "baseline": baseline,
            "candidate": candidate,
            "verdict": verdict,
            "baseline_already_blocks": (
                expected == 403 and baseline_code == 403
            ),
        })

    counts = {
        label: sum(item["verdict"] == label for item in results)
        for label in [
            "pass",
            "fail",
            "error",
            "inconclusive",
            "known_application_issue",
        ]
    }

    status = (
        "http_checks_failed"
        if counts["fail"] or counts["error"]
        else "review_required"
    )

    report = {
        "scope": "HTTP response checks only",
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "compiler_version": compiled["compiler_version"],
        "expected_rule_ids": compiled["rule_ids"],
        "counts": counts,
        "cases": results,
        "remaining_gates": [
            "Verify loaded candidate bytes match compiled_sha256",
            "Record configuration syntax validation",
            "Correlate requests with AutoShield WAF rule IDs",
            "Review unresolved application errors and inconclusive results",
            "Review added coverage and false positives",
        ],
        "deployment_ready": False,
    }

    with closing(connect_db()) as db:
        with db:
            result = db.execute(
                """
                INSERT INTO validation_runs (
                    proposal_id,
                    compiled_sha256,
                    status,
                    report,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    proposal_id,
                    compiled["sha256"],
                    status,
                    json.dumps(report),
                    started_at,
                ),
            )

            run_id = result.lastrowid

    return {
        "id": run_id,
        "proposal_id": proposal_id,
        "compiled_sha256": compiled["sha256"],
        "status": status,
        "report": report,
    }


def read_validations(limit=20):
    with closing(connect_db()) as db:
        rows = db.execute(
            """
            SELECT * FROM validation_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return {
        "validation_runs": [
            {
                "id": row["id"],
                "proposal_id": row["proposal_id"],
                "compiled_sha256": row["compiled_sha256"],
                "status": row["status"],
                "report": json.loads(row["report"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    }