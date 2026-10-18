import json
import re
from contextlib import closing
from datetime import datetime, timezone

from proposals import connect_db


HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def initialize_evidence():
    with closing(connect_db()) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS validation_evidence (
                id INTEGER PRIMARY KEY,
                validation_run_id INTEGER NOT NULL,
                probe_id TEXT NOT NULL,
                source TEXT NOT NULL,
                report TEXT NOT NULL,
                attached_at TEXT NOT NULL,
                FOREIGN KEY (validation_run_id)
                    REFERENCES validation_runs(id),
                UNIQUE(probe_id)
            )
        """)
        db.commit()


def attach_evidence(run_id, report):
    encoded = json.dumps(report)

    if len(encoded.encode("utf-8")) > 65536:
        raise ValueError("Evidence report exceeds 64 KiB")

    probe_id = report.get("probe_id")

    if (
        not isinstance(probe_id, str)
        or not re.fullmatch(r"[0-9a-f]{32}", probe_id)
    ):
        raise ValueError("Invalid probe ID")

    expected_hash = report.get("expected_compiled_sha256")

    if (
        not isinstance(expected_hash, str)
        or not HASH_PATTERN.fullmatch(expected_hash)
    ):
        raise ValueError("Invalid compiled SHA-256")

    if (
        report.get("candidate_match_verified") is not True
        or report.get("syntax_check") != "passed"
        or report.get("probe_http_status") != 403
    ):
        raise ValueError("Report does not contain a verified blocking probe")

    if (
        report.get("rule_file_sha256_before") != expected_hash
        or report.get("rule_file_sha256_after") != expected_hash
    ):
        raise ValueError("Rule-file hashes do not match")

    with closing(connect_db()) as db:
        with db:
            db.execute("BEGIN IMMEDIATE")

            run = db.execute(
                "SELECT * FROM validation_runs WHERE id = ?",
                (run_id,),
            ).fetchone()

            if run is None:
                raise LookupError("Validation run not found")

            if report.get("proposal_id") != run["proposal_id"]:
                raise ValueError("Evidence belongs to a different proposal")

            if expected_hash != run["compiled_sha256"]:
                raise ValueError("Evidence hash differs from validation hash")

            saved_report = json.loads(run["report"])
            expected_ids = {
                str(value)
                for value in saved_report.get("expected_rule_ids", [])
            }

            transactions = report.get("audit_transactions")

            if not isinstance(transactions, list):
                raise ValueError("Audit transactions are missing")

            matching_transaction = False

            for transaction in transactions:
                if not isinstance(transaction, dict):
                    continue

                ids = transaction.get("matched_rule_ids", [])

                if not isinstance(ids, list):
                    continue

                if (
                    transaction.get("http_status") == 403
                    and transaction.get("interrupted") is True
                    and expected_ids.intersection(str(value) for value in ids)
                ):
                    matching_transaction = True

            if not matching_transaction:
                raise ValueError("No expected rule ID in blocking evidence")

            existing = db.execute(
                """
                SELECT id, validation_run_id, report
                FROM validation_evidence
                WHERE probe_id = ?
                """,
                (probe_id,),
            ).fetchone()

            if existing:
                if (
                    existing["validation_run_id"] != run_id
                    or json.loads(existing["report"]) != report
                ):
                    raise ValueError("Probe ID already has different evidence")

                return {
                    "created": False,
                    "evidence_id": existing["id"],
                    "validation_run_id": run_id,
                }

            result = db.execute(
                """
                INSERT INTO validation_evidence (
                    validation_run_id,
                    probe_id,
                    source,
                    report,
                    attached_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    probe_id,
                    "local_host_report",
                    encoded,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

            return {
                "created": True,
                "evidence_id": result.lastrowid,
                "validation_run_id": run_id,
                "source": "local_host_report",
                "deployment_ready": False,
            }


def read_evidence(run_id):
    with closing(connect_db()) as db:
        run = db.execute(
            "SELECT id FROM validation_runs WHERE id = ?",
            (run_id,),
        ).fetchone()

        if run is None:
            raise LookupError("Validation run not found")

        rows = db.execute(
            """
            SELECT * FROM validation_evidence
            WHERE validation_run_id = ?
            ORDER BY id DESC
            LIMIT 20
            """,
            (run_id,),
        ).fetchall()

    return {
        "validation_run_id": run_id,
        "evidence": [
            {
                "id": row["id"],
                "source": row["source"],
                "attached_at": row["attached_at"],
                "report": json.loads(row["report"]),
            }
            for row in rows
        ],
    }
