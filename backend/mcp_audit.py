"""Durable decision-before-execution audit. Payloads stored as hashes, not raw input."""
import json
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
from datetime import datetime, timezone

class Audit:
    def __init__(self, path=None):
        self.path = path or os.getenv("MCP_AUDIT_DB", "/data/mcp-audit.db")
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS denies(fingerprint TEXT PRIMARY KEY, created_at TEXT NOT NULL)")
    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()
    def emit(self, **event):
        event["at"] = datetime.now(timezone.utc).isoformat()
        with self.connect() as db:
            cursor = db.execute("INSERT INTO events(body) VALUES(?)", (json.dumps(event),))
            return {"id": cursor.lastrowid, **event}
    def events(self, after=0, limit=150):
        with self.connect() as db:
            rows = db.execute("SELECT id,body FROM events WHERE id>? ORDER BY id LIMIT ?", (after, min(limit, 500))).fetchall()
        return [{"id": row[0], **json.loads(row[1])} for row in rows]
    def recent(self):
        with self.connect() as db:
            rows = db.execute("SELECT id,body FROM events ORDER BY id DESC LIMIT 150").fetchall()
        return [{"id": row[0], **json.loads(row[1])} for row in reversed(rows)]
    def denied(self, digest):
        with self.connect() as db:
            return db.execute("SELECT 1 FROM denies WHERE fingerprint=?", (digest,)).fetchone() is not None
    def tighten(self, digest):
        with self.connect() as db:
            return db.execute("INSERT OR IGNORE INTO denies VALUES(?,?)", (digest, datetime.now(timezone.utc).isoformat())).rowcount > 0
