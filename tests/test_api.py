"""
test_api.py — API route tests without an HTTP client.

We call the route functions directly. Sync routes are called normally;
the one async route (ingest) is called with asyncio.run().

The JSONResponse returned by the empty-ingest path is unwrapped via .body.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

# ---- Point the API at a temp DB before importing the app ---------------
_FIXTURE_DIR = Path(__file__).parent / "fixtures"
_FIXTURE_DIR.mkdir(exist_ok=True)
_TEST_DB = str(_FIXTURE_DIR / "test_api.db")
os.environ["SENTINELLITE_DB"] = _TEST_DB

_db_path = Path(_TEST_DB)
if _db_path.exists():
    _db_path.unlink()

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from sentinellite.api import alerts_for_ip, get_alert, ingest, list_alerts, stats
from sentinellite.models import Alert
from sentinellite.storage import init_db, save_alerts

_NOW = datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc)


def _seed_alert(ip: str = "1.2.3.4", rule: str = "brute_force") -> Alert:
    conn = init_db(_db_path)
    alert = Alert(
        rule_id=rule, severity="high", mitre_id="T1110.001",
        source_ip=ip, user="root", count=10, window_minutes=10,
        first_seen=_NOW, last_seen=_NOW, evidence=["line1"], risk_score=70,
    )
    saved = save_alerts(conn, [alert])
    conn.close()
    return saved[0]


@pytest.fixture(autouse=True)
def clean_db():
    if _db_path.exists():
        _db_path.unlink()
    yield
    if _db_path.exists():
        _db_path.unlink()


# ---- Sync route tests --------------------------------------------------
# list_alerts, get_alert, alerts_for_ip, stats are all sync def routes.

def test_list_alerts_empty():
    result = list_alerts()
    assert result == []


def test_list_alerts_returns_data():
    _seed_alert()
    result = list_alerts()
    assert len(result) == 1
    assert result[0].rule_id == "brute_force"


def test_get_alert_by_id():
    saved = _seed_alert()
    result = get_alert(saved.id)
    assert result.id == saved.id


def test_get_alert_not_found():
    with pytest.raises(HTTPException) as exc_info:
        get_alert(9999)
    assert exc_info.value.status_code == 404


def test_alerts_for_ip():
    _seed_alert(ip="2.2.2.2")
    result = alerts_for_ip("2.2.2.2")
    assert len(result) == 1
    assert result[0].source_ip == "2.2.2.2"


def test_alerts_for_ip_invalid():
    with pytest.raises(HTTPException) as exc_info:
        alerts_for_ip("not-an-ip")
    assert exc_info.value.status_code == 400


def test_stats_endpoint():
    _seed_alert()
    result = stats()
    assert result["total_alerts"] >= 1
    assert "severity_counts" in result


# ---- Async route tests (ingest is async) --------------------------------

class _FakeRequest:
    """Minimal mock of fastapi.Request for the ingest route."""
    def __init__(self, body: bytes):
        self._body = body

    async def body(self) -> bytes:
        return self._body


def test_ingest_valid_log():
    lines = [
        f"Jun 15 10:0{i}:00 host sshd[1]: Failed password for root from 3.3.3.3 port 22 ssh2"
        for i in range(10)
    ]
    req = _FakeRequest("\n".join(lines).encode())
    result = asyncio.run(ingest(req))
    assert result["events_parsed"] == 10


def test_ingest_oversized_body():
    req = _FakeRequest(b"x" * (3 * 1024 * 1024))  # 3 MB > 2 MB limit
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(ingest(req))
    assert exc_info.value.status_code == 413


def test_ingest_empty_body():
    req = _FakeRequest(b"")
    result = asyncio.run(ingest(req))
    # ingest returns JSONResponse for "no events" case; unwrap it
    if isinstance(result, JSONResponse):
        data = json.loads(result.body)
    else:
        data = result
    assert data["alerts"] == []
