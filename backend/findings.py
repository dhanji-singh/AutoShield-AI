import os
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

from detector import classify_event, DETECTOR_VERSION


DB_PATH = os.getenv("AUTOSHIELD_DB_PATH", "/app/data/autoshield.db")


def connect_db():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize_findings():
    with closing(connect_db()) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                event_id INTEGER NOT NULL,
                detector_version TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'suspected',
                matched_rules TEXT NOT NULL,
                reasons TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (event_id) REFERENCES events(id),
                UNIQUE(event_id, detector_version)
            );

            CREATE TABLE IF NOT EXISTS finding_cursors (
                detector_version TEXT PRIMARY KEY,
                last_event_id INTEGER NOT NULL
            );
        """)
        db.commit()


def scan_findings():
    created = 0

    with closing(connect_db()) as db:
        with db:
            # Serialize scans and commit findings + cursor together.
            db.execute("BEGIN IMMEDIATE")

            cursor = db.execute(
                """
                SELECT last_event_id
                FROM finding_cursors
                WHERE detector_version = ?
                """,
                (DETECTOR_VERSION,),
            ).fetchone()

            last_id = cursor["last_event_id"] if cursor else 0

            rows = db.execute(
                """
                SELECT id, payload
                FROM events
                WHERE id > ?
                ORDER BY id
                LIMIT 500
                """,
                (last_id,),
            ).fetchall()

            for row in rows:
                event = json.loads(row["payload"])
                detection = classify_event(event)

                if detection["status"] == "suspicious":
                    result = db.execute(
                        """
                        INSERT INTO findings (
                            event_id,
                            detector_version,
                            attack_type,
                            status,
                            matched_rules,
                            reasons,
                            created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(event_id, detector_version)
                        DO NOTHING
                        """,
                        (
                            row["id"],
                            DETECTOR_VERSION,
                            detection["attack_type"],
                            "suspected",
                            json.dumps(detection["matched_rules"]),
                            json.dumps(detection["reasons"]),
                            datetime.now(timezone.utc).isoformat(),
                        ),
                    )

                    created += result.rowcount

                last_id = row["id"]

            db.execute(
                """
                INSERT INTO finding_cursors (
                    detector_version, last_event_id
                )
                VALUES (?, ?)
                ON CONFLICT(detector_version) DO UPDATE SET
                    last_event_id = excluded.last_event_id
                """,
                (DETECTOR_VERSION, last_id),
            )

    return {
        "scanned": len(rows),
        "created": created,
        "last_event_id": last_id,
    }


def read_findings(limit=20, before_id=None):
    with closing(connect_db()) as db:
        with db:
            # Read the count and page from one database snapshot.
            db.execute("BEGIN")

            total = db.execute(
                "SELECT COUNT(*) FROM findings"
            ).fetchone()[0]

            rows = db.execute(
                """
                SELECT
                    f.*,
                    e.payload AS event_payload
                FROM findings AS f
                JOIN events AS e ON e.id = f.event_id
                WHERE (? IS NULL OR f.id < ?)
                ORDER BY f.id DESC
                LIMIT ?
                """,
                (before_id, before_id, limit),
            ).fetchall()

    items = []

    for row in rows:
        items.append(
            {
                "id": row["id"],
                "event_id": row["event_id"],
                "attack_type": row["attack_type"],
                "status": row["status"],
                "detector_version": row["detector_version"],
                "matched_rules": json.loads(row["matched_rules"]),
                "reasons": json.loads(row["reasons"]),
                "created_at": row["created_at"],
                "request": json.loads(row["event_payload"]),
            }
        )

    return {
        "total_findings": total,
        "findings": items,
        "next_before_id": rows[-1]["id"] if rows else None,
    }