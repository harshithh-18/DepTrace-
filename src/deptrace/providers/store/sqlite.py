"""SQLite persistence for scan state.

SQLite is the default because it is the only database that needs no service,
no credentials, and no setup — a clean clone can persist scans immediately.
Postgres remains an option behind the same `StateStore` protocol for anyone
who wants shared history; nothing in the core changes to support it.

The schema is deliberately minimal: the full `RunState` is stored as JSON in
one column, with a few fields lifted out as real columns purely so scans can
be listed and filtered without deserializing every row.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from deptrace.core.state import RunState

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id     TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    reachable   INTEGER NOT NULL DEFAULT 0,
    total_vulns INTEGER NOT NULL DEFAULT 0,
    state_json  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans (created_at DESC);
"""


class SQLiteStateStore:
    """Stores `RunState` rows in a local SQLite file."""

    def __init__(self, path: Path | str | None = None) -> None:
        if path is None:
            path = Path.home() / ".cache" / "deptrace" / "scans.db"
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def save(self, state: RunState) -> None:
        """Upsert one scan. Safe to call repeatedly during a run."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans
                    (scan_id, target, status, created_at, reachable, total_vulns, state_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    status      = excluded.status,
                    reachable   = excluded.reachable,
                    total_vulns = excluded.total_vulns,
                    state_json  = excluded.state_json
                """,
                (
                    state.scan_id,
                    state.target,
                    state.status,
                    state.created_at.isoformat(),
                    state.metrics.reachable,
                    state.metrics.total_vulnerabilities,
                    state.model_dump_json(),
                ),
            )

    def load(self, scan_id: str) -> RunState | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state_json FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        if row is None:
            return None
        try:
            return RunState.model_validate_json(row[0])
        except (ValueError, json.JSONDecodeError):
            return None  # a corrupt row must not crash the CLI

    def list_scans(self, limit: int = 20) -> list[RunState]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT state_json FROM scans ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()

        scans: list[RunState] = []
        for row in rows:
            try:
                scans.append(RunState.model_validate_json(row[0]))
            except (ValueError, json.JSONDecodeError):
                continue
        return scans
