"""Scan history in one SQLite file (no database server to install).

Every scan run is kept, so the dashboard can show the score trend and the
drift between a host's baseline scan and its latest scan.

SECURITY: the history shows the weak spots of every scanned machine. Keep the
.db file out of Git (data/ is in .gitignore) and off shared drives.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    trigger TEXT NOT NULL,            -- manual (dashboard button), scheduled, cli
    inventory TEXT NOT NULL,
    organisation TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS host_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    host TEXT NOT NULL,
    platform TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'server',
    transport TEXT NOT NULL,
    location TEXT NOT NULL DEFAULT '',
    error TEXT,                       -- set when the host could not be scanned at all
    scanned_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS results (
    host_scan_id INTEGER NOT NULL REFERENCES host_scans(id),
    control_id TEXT NOT NULL,
    data TEXT NOT NULL                -- Result.to_dict() as JSON (control text kept as it was)
);
CREATE TABLE IF NOT EXISTS baselines (
    host TEXT PRIMARY KEY,
    host_scan_id INTEGER NOT NULL REFERENCES host_scans(id),
    set_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_results_scan ON results(host_scan_id);
CREATE INDEX IF NOT EXISTS ix_hostscans_host ON host_scans(host, id);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._db()) as db, db:
            db.executescript(SCHEMA)

    # WHY: a new connection per call, so the web server's threads never share one.
    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        return db

    # ------------------------------------------------------------------ writing
    def start_run(self, trigger: str, inventory: str, organisation: str) -> int:
        with closing(self._db()) as db, db:
            return db.execute("INSERT INTO runs(started_at, trigger, inventory, organisation) "
                              "VALUES (?,?,?,?)", (now(), trigger, inventory, organisation)).lastrowid

    def finish_run(self, run_id: int) -> None:
        with closing(self._db()) as db, db:
            db.execute("UPDATE runs SET finished_at=? WHERE id=?", (now(), run_id))

    def add_host_scan(self, run_id: int, host, results: list[dict[str, Any]],
                      error: str | None = None) -> int:
        with closing(self._db()) as db, db:
            hs = db.execute(
                "INSERT INTO host_scans(run_id, host, platform, role, kind, transport, location,"
                " error, scanned_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (run_id, host.name, host.platform, host.role, host.kind, host.transport,
                 host.location, error, now())).lastrowid
            db.executemany("INSERT INTO results(host_scan_id, control_id, data) VALUES (?,?,?)",
                           [(hs, r["control_id"], json.dumps(r, default=str)) for r in results])
            return hs

    def set_baseline(self, host: str, host_scan_id: int | None = None) -> int | None:
        with closing(self._db()) as db, db:
            if host_scan_id is None:
                row = db.execute("SELECT id FROM host_scans WHERE host=? AND error IS NULL "
                                 "ORDER BY id DESC LIMIT 1", (host,)).fetchone()
                if not row:
                    return None
                host_scan_id = row["id"]
            db.execute("INSERT OR REPLACE INTO baselines(host, host_scan_id, set_at) VALUES (?,?,?)",
                       (host, host_scan_id, now()))
            return host_scan_id

    # ------------------------------------------------------------------ reading
    def runs(self, limit: int = 30) -> list[dict[str, Any]]:
        with closing(self._db()) as db:
            rows = db.execute("SELECT * FROM runs WHERE finished_at IS NOT NULL "
                              "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in reversed(rows)]

    def host_scans(self, run_id: int) -> list[dict[str, Any]]:
        with closing(self._db()) as db:
            return [dict(r) for r in db.execute(
                "SELECT * FROM host_scans WHERE run_id=? ORDER BY host", (run_id,))]

    def results(self, host_scan_id: int) -> list[dict[str, Any]]:
        with closing(self._db()) as db:
            return [json.loads(r["data"]) for r in db.execute(
                "SELECT data FROM results WHERE host_scan_id=? ORDER BY control_id", (host_scan_id,))]

    def previous_host_scan(self, host: str, before_id: int) -> dict[str, Any] | None:
        with closing(self._db()) as db:
            row = db.execute("SELECT * FROM host_scans WHERE host=? AND id<? AND error IS NULL "
                             "ORDER BY id DESC LIMIT 1", (host, before_id)).fetchone()
        return dict(row) if row else None

    def baseline(self, host: str) -> dict[str, Any] | None:
        with closing(self._db()) as db:
            row = db.execute("SELECT hs.*, b.set_at AS baseline_set_at FROM baselines b "
                             "JOIN host_scans hs ON hs.id=b.host_scan_id WHERE b.host=?",
                             (host,)).fetchone()
        return dict(row) if row else None
