"""SQLite audit trail of repair runs and every candidate patch with its gate verdict.

Only a SHA-256 of the input manifest is stored, never the manifest itself (it may hold secrets).
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .repair import RepairReport

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    source_name TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    proposer TEXT NOT NULL,
    model TEXT,
    llm_calls INTEGER NOT NULL DEFAULT 0,
    degraded TEXT,
    summary_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    resource TEXT NOT NULL,
    control_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    proposer TEXT NOT NULL,
    simulated INTEGER NOT NULL,
    accepted INTEGER NOT NULL,
    patch_json TEXT,
    reasons_json TEXT NOT NULL,
    latency_ms REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_attempts_run ON attempts(run_id);
"""


class AuditStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._memory_conn = sqlite3.connect(":memory:") if str(self.path) == ":memory:" else None
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = self._memory_conn or sqlite3.connect(self.path)
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if self._memory_conn is None:
                conn.close()

    def record(self, report: RepairReport, source_name: str, model: str | None = None) -> int:
        with self._conn() as c:  # single transaction: a run is stored completely or not at all
            cur = c.execute(
                "INSERT INTO runs (created_at, source_name, source_sha256, proposer, model, llm_calls, degraded, summary_json)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"), source_name[:200], report.source_sha256,
                 report.proposer, model, report.llm_calls, report.degraded, json.dumps(report.summary)),
            )
            run_id = int(cur.lastrowid)
            for o in report.outcomes:
                rows = o.attempts or []
                if not rows:
                    c.execute(
                        "INSERT INTO attempts (run_id, resource, control_id, subject, status, attempt, proposer, simulated,"
                        " accepted, patch_json, reasons_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (run_id, o.finding["resource"], o.finding["control_id"], o.finding["subject"], o.status, 0,
                         "-", 0, 0, None, "[]"))
                for a in rows:
                    c.execute(
                        "INSERT INTO attempts (run_id, resource, control_id, subject, status, attempt, proposer, simulated,"
                        " accepted, patch_json, reasons_json, latency_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (run_id, o.finding["resource"], o.finding["control_id"], o.finding["subject"], o.status, a.attempt,
                         a.proposer, int(a.simulated), int(a.accepted), json.dumps(a.patch) if a.patch is not None else None,
                         json.dumps(a.reasons), a.latency_ms))
        return run_id

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            rows = c.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall()
        return [{**dict(r), "summary": json.loads(r["summary_json"])} for r in rows]

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            run = c.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if run is None:
                return None
            attempts = c.execute("SELECT * FROM attempts WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()
        return {**dict(run), "summary": json.loads(run["summary_json"]),
                "attempts": [{**dict(a), "patch": json.loads(a["patch_json"]) if a["patch_json"] else None,
                              "reasons": json.loads(a["reasons_json"])} for a in attempts]}
