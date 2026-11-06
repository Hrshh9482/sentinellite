"""
storage.py — SQLite persistence for events and alerts.

Why SQLite? Zero external dependencies, single-file database, good enough
for a portfolio SIEM that processes files rather than live streams.

All queries use parameterised placeholders — never string interpolation —
to prevent SQL injection even though the data is locally sourced.

Privacy: we store only metadata. Raw event lines and alert evidence are
NOT stored in the events table. Evidence is stored per-alert but capped
at 10 lines of 512 chars each by the Alert model validator.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinellite.models import Alert, Event


def _connect(db_path: Path) -> sqlite3.Connection:
    """Open a connection with foreign keys enabled and WAL journal for safety."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(db_path: Path) -> sqlite3.Connection:
    """Create tables if they don't exist; return open connection."""
    conn = _connect(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            source_ip   TEXT    NOT NULL,
            user        TEXT    NOT NULL,
            action      TEXT    NOT NULL,
            outcome     TEXT    NOT NULL
            -- raw line intentionally NOT stored: privacy rule 10
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id         TEXT    NOT NULL,
            severity        TEXT    NOT NULL,
            mitre_id        TEXT    NOT NULL,
            source_ip       TEXT    NOT NULL,
            user            TEXT    NOT NULL,
            count           INTEGER NOT NULL,
            window_minutes  INTEGER NOT NULL,
            first_seen      TEXT    NOT NULL,
            last_seen       TEXT    NOT NULL,
            evidence        TEXT    NOT NULL,  -- JSON array, capped by model
            risk_score      INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_events_ip    ON events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_alerts_ip    ON alerts(source_ip);
        CREATE INDEX IF NOT EXISTS idx_alerts_rule  ON alerts(rule_id);
    """)
    conn.commit()
    return conn


def save_events(conn: sqlite3.Connection, events: list[Event]) -> None:
    """Bulk-insert events (metadata only, no raw content)."""
    rows = [
        (
            ev.timestamp.isoformat(),
            ev.source_ip,
            ev.user,
            ev.action,
            ev.outcome,
        )
        for ev in events
    ]
    conn.executemany(
        "INSERT INTO events (timestamp, source_ip, user, action, outcome) VALUES (?,?,?,?,?)",
        rows,
    )
    conn.commit()


def save_alerts(conn: sqlite3.Connection, alerts: list[Alert]) -> list[Alert]:
    """
    Insert alerts and return them with their database-assigned IDs.
    Evidence is JSON-serialised (already capped by Alert.cap_evidence).
    """
    result: list[Alert] = []
    for alert in alerts:
        cur = conn.execute(
            """INSERT INTO alerts
               (rule_id, severity, mitre_id, source_ip, user, count,
                window_minutes, first_seen, last_seen, evidence, risk_score)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                alert.rule_id,
                alert.severity,
                alert.mitre_id,
                alert.source_ip,
                alert.user,
                alert.count,
                alert.window_minutes,
                alert.first_seen.isoformat(),
                alert.last_seen.isoformat(),
                json.dumps(alert.evidence),
                alert.risk_score,
            ),
        )
        result.append(alert.model_copy(update={"id": cur.lastrowid}))
    conn.commit()
    return result


def _row_to_alert(row: sqlite3.Row) -> Alert:
    return Alert(
        id=row["id"],
        rule_id=row["rule_id"],
        severity=row["severity"],
        mitre_id=row["mitre_id"],
        source_ip=row["source_ip"],
        user=row["user"],
        count=row["count"],
        window_minutes=row["window_minutes"],
        first_seen=datetime.fromisoformat(row["first_seen"]),
        last_seen=datetime.fromisoformat(row["last_seen"]),
        evidence=json.loads(row["evidence"]),
        risk_score=row["risk_score"],
    )


def get_all_alerts(conn: sqlite3.Connection) -> list[Alert]:
    rows = conn.execute("SELECT * FROM alerts ORDER BY last_seen DESC").fetchall()
    return [_row_to_alert(r) for r in rows]


def get_alert_by_id(conn: sqlite3.Connection, alert_id: int) -> Alert | None:
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row_to_alert(row) if row else None


def get_alerts_by_ip(conn: sqlite3.Connection, ip: str) -> list[Alert]:
    rows = conn.execute(
        "SELECT * FROM alerts WHERE source_ip = ? ORDER BY last_seen DESC", (ip,)
    ).fetchall()
    return [_row_to_alert(r) for r in rows]


def get_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    """Return summary statistics from stored data."""
    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    severity_counts: dict[str, int] = {}
    for row in conn.execute("SELECT severity, COUNT(*) as c FROM alerts GROUP BY severity"):
        severity_counts[row["severity"]] = row["c"]

    top_attackers = [
        {"ip": r["source_ip"], "alert_count": r["c"]}
        for r in conn.execute(
            "SELECT source_ip, COUNT(*) as c FROM alerts "
            "WHERE source_ip NOT IN ('unknown','multiple') "
            "GROUP BY source_ip ORDER BY c DESC LIMIT 10"
        )
    ]

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "severity_counts": severity_counts,
        "top_attackers": top_attackers,
    }
