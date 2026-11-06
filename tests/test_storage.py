"""
test_storage.py — Storage layer tests.
Verifies that raw content is NOT persisted (privacy rule 10).
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sentinellite.models import Alert, Event
from sentinellite.storage import (
    get_alert_by_id,
    get_alerts_by_ip,
    get_all_alerts,
    get_stats,
    save_alerts,
    save_events,
)

_NOW = datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc)


def _make_event(ip: str = "1.2.3.4", user: str = "root") -> Event:
    return Event(
        timestamp=_NOW,
        source_ip=ip,
        user=user,
        action="failed_password",
        outcome="failure",
        raw="Jun 15 10:00:00 host sshd[1]: Failed password for root from 1.2.3.4",
    )


def _make_alert(ip: str = "1.2.3.4", rule: str = "brute_force") -> Alert:
    return Alert(
        rule_id=rule,
        severity="high",
        mitre_id="T1110.001",
        source_ip=ip,
        user="root",
        count=10,
        window_minutes=10,
        first_seen=_NOW,
        last_seen=_NOW,
        evidence=["line1", "line2"],
        risk_score=70,
    )


def test_save_and_retrieve_alerts(tmp_db):
    alerts = [_make_alert()]
    saved = save_alerts(tmp_db, alerts)
    assert saved[0].id is not None

    all_alerts = get_all_alerts(tmp_db)
    assert len(all_alerts) == 1
    assert all_alerts[0].rule_id == "brute_force"


def test_get_alert_by_id(tmp_db):
    saved = save_alerts(tmp_db, [_make_alert()])[0]
    found = get_alert_by_id(tmp_db, saved.id)
    assert found is not None
    assert found.id == saved.id


def test_get_alert_by_id_not_found(tmp_db):
    assert get_alert_by_id(tmp_db, 9999) is None


def test_get_alerts_by_ip(tmp_db):
    save_alerts(tmp_db, [_make_alert("1.2.3.4"), _make_alert("5.6.7.8")])
    results = get_alerts_by_ip(tmp_db, "1.2.3.4")
    assert len(results) == 1
    assert results[0].source_ip == "1.2.3.4"


def test_stats(tmp_db):
    save_events(tmp_db, [_make_event()])
    save_alerts(tmp_db, [_make_alert()])
    stats = get_stats(tmp_db)
    assert stats["total_events"] == 1
    assert stats["total_alerts"] == 1
    assert "high" in stats["severity_counts"]


def test_raw_content_not_persisted(tmp_db):
    """
    Privacy rule 10: raw log line content must NOT be stored in the events table.
    We verify the events table has no column for raw content.
    """
    save_events(tmp_db, [_make_event()])
    # Get column names from the events table
    cursor = tmp_db.execute("PRAGMA table_info(events)")
    columns = {row["name"] for row in cursor.fetchall()}
    assert "raw" not in columns, "Raw log content must NOT be persisted in the events table"


def test_evidence_capped_in_db(tmp_db):
    """Evidence stored in DB must not exceed 10 lines (enforced by Alert model)."""
    alert = Alert(
        rule_id="brute_force",
        severity="high",
        mitre_id="T1110.001",
        source_ip="1.2.3.4",
        user="root",
        count=15,
        window_minutes=10,
        first_seen=_NOW,
        last_seen=_NOW,
        evidence=[f"line {i}" for i in range(15)],  # 15 lines -> should be capped to 10
        risk_score=70,
    )
    saved = save_alerts(tmp_db, [alert])[0]
    found = get_alert_by_id(tmp_db, saved.id)
    assert len(found.evidence) <= 10
