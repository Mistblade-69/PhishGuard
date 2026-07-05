"""
history.py
Persistent storage for every analysis run (email, screenshot, PDF), using
SQLite so results survive app restarts -- unlike the old feedback_log.json
approach, which only tracked corrections, not full analysis history.

100% normal code -- no AI.
"""

import sqlite3
import json
import os
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "history.db")


def _get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_type TEXT NOT NULL,        -- 'eml' | 'pasted' | 'screenshot' | 'pdf'
            identifier TEXT,                  -- filename or subject
            verdict TEXT,
            confidence INTEGER,
            techniques TEXT,                  -- JSON list
            reasoning TEXT,                   -- JSON list
            evidence_json TEXT,               -- full evidence dump
            malware_flags TEXT                -- JSON list, may be empty
        )
    """)
    conn.commit()
    return conn


def save_analysis(source_type: str, identifier: str, verdict: dict, evidence: dict = None, malware_flags: list = None) -> int:
    conn = _get_conn()
    cur = conn.execute(
        """INSERT INTO analyses
           (timestamp, source_type, identifier, verdict, confidence, techniques, reasoning, evidence_json, malware_flags)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.now(timezone.utc).isoformat(),
            source_type,
            identifier,
            verdict.get("verdict", "unknown"),
            verdict.get("confidence", 0),
            json.dumps(verdict.get("techniques_detected", [])),
            json.dumps(verdict.get("reasoning", [])),
            json.dumps(evidence or {}),
            json.dumps(malware_flags or []),
        ),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id


def get_all_analyses(limit: int = 100) -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM analyses ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    columns = [d[0] for d in conn.execute("SELECT * FROM analyses LIMIT 0").description]
    conn.close()
    return [dict(zip(columns, row)) for row in rows]


def get_stats() -> dict:
    conn = _get_conn()
    total = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
    by_verdict = dict(conn.execute(
        "SELECT verdict, COUNT(*) FROM analyses GROUP BY verdict"
    ).fetchall())
    by_source = dict(conn.execute(
        "SELECT source_type, COUNT(*) FROM analyses GROUP BY source_type"
    ).fetchall())
    conn.close()
    return {"total": total, "by_verdict": by_verdict, "by_source_type": by_source}


def clear_history():
    conn = _get_conn()
    conn.execute("DELETE FROM analyses")
    conn.commit()
    conn.close()