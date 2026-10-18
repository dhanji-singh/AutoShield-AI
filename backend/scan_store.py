from scan_identity import deduplicate_findings
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).isoformat()


def connect():
    path = os.getenv("AUTOSHIELD_DB_PATH", "/app/data/autoshield.db")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    return db


def initialize():
    with closing(connect()) as db, db:
        db.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY, target TEXT NOT NULL, options TEXT NOT NULL,
            status TEXT NOT NULL, created_at TEXT NOT NULL, finished_at TEXT,
            cancel_requested INTEGER NOT NULL DEFAULT 0, report TEXT NOT NULL,
            ai_review TEXT)""")
        # A single backend worker owns scans; interrupted work is never silently resumed.
        for row in db.execute("SELECT id,report FROM scans WHERE status IN ('queued','running')").fetchall():
            report = json.loads(row["report"])
            report.update(status="interrupted", stop_reason="Backend restarted before the assessment finished.")
            close_activity(report)
            db.execute("UPDATE scans SET status='interrupted',report=?,finished_at=? WHERE id=?",
                       (json.dumps(report), now(), row["id"]))


def create(target, options):
    with closing(connect()) as db, db:
        cursor = db.execute("INSERT INTO scans(target,options,status,created_at,report) VALUES(?,?,?,?,?)",
                            (target, json.dumps(options), "queued", now(), json.dumps({"pages": [], "findings": [], "errors": [], "requests_sent": 0})))
        return cursor.lastrowid


def serialize(row):
    result = dict(row)
    for key in ("options", "report", "ai_review"):
        result[key] = json.loads(result[key]) if result[key] else None
    if result.get("report"):
        result["report"]["findings"] = deduplicate_findings(result["report"].get("findings", []))
    result["cancel_requested"] = bool(result["cancel_requested"])
    return result


def get(scan_id):
    with closing(connect()) as db:
        row = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if row is None:
        raise LookupError("Scan not found")
    return serialize(row)


def history(limit=50):
    with closing(connect()) as db:
        rows = db.execute("SELECT id,target,status,created_at,finished_at FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def close_activity(report):
    for run in report.get("check_runs", []):
        if run["status"] in ("running", "response_received"):
            run.update(status="stopped", reason=report.get("stop_reason") or "Assessment ended before this check finished.", finished_at=now())
    if report.get("timeline") and report["timeline"][-1].get("message") != "Assessment " + report["status"]:
        report["current_activity"] = "Assessment " + report["status"]
        report["timeline"].append({"id": len(report["timeline"]) + 1, "at": now(),
            "stage": "session", "message": report["current_activity"], "reason": report.get("stop_reason")})


def save(scan_id, report, final=False):
    report["findings"] = deduplicate_findings(report.get("findings", []))
    if final:
        close_activity(report)
    with closing(connect()) as db, db:
        db.execute("UPDATE scans SET status=?,report=?,finished_at=? WHERE id=?", (
            report["status"], json.dumps(report), now() if final else None, scan_id))


def cancel(scan_id):
    get(scan_id)
    with closing(connect()) as db, db:
        db.execute("UPDATE scans SET cancel_requested=1 WHERE id=? AND status IN ('queued','running')", (scan_id,))


def cancelled(scan_id):
    with closing(connect()) as db:
        row = db.execute("SELECT cancel_requested FROM scans WHERE id=?", (scan_id,)).fetchone()
    return row is None or bool(row["cancel_requested"])


def save_ai(scan_id, review):
    with closing(connect()) as db, db:
        db.execute("UPDATE scans SET ai_review=? WHERE id=?", (json.dumps(review), scan_id))
