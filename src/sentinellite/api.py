"""
api.py — FastAPI REST API for SentinelLite.

Binds to 127.0.0.1:8000 only. All data comes from an SQLite database
that must be populated via the CLI first (or via POST /ingest).

Security notes:
- No auth token is implemented here because this is a local-only API.
  A real deployment would add the bearer-token middleware from the
  ThreatScan rules, but that is out of scope for this portfolio project.
- Request body size is capped at 2 MB (config.yaml: api_max_body_bytes).
- All input is validated by Pydantic before touching the database.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from sentinellite.detection.engine import DetectionEngine, load_rules
from sentinellite.models import Alert
from sentinellite.parsers.ssh_auth import SSHAuthParser
from sentinellite.storage import (
    get_alert_by_id,
    get_alerts_by_ip,
    get_all_alerts,
    get_stats,
    init_db,
    save_alerts,
    save_events,
)

# ---------------------------------------------------------------------------
# Config & DB path (resolved relative to project root via env var or default)
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).parent.parent.parent.parent  # sentinellite/
_CONFIG_PATH = _PROJECT_ROOT / "config.yaml"
_DB_PATH = Path(os.environ.get("SENTINELLITE_DB", str(_PROJECT_ROOT / "sentinel.db")))

_config: dict = {}
if _CONFIG_PATH.exists():
    with _CONFIG_PATH.open(encoding="utf-8") as _f:
        _config = yaml.safe_load(_f) or {}

_MAX_BODY = _config.get("api_max_body_bytes", 2 * 1024 * 1024)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SentinelLite API",
    description="Mini-SIEM alert query and log ingest API. Local use only.",
    version="0.1.0",
)


def _get_conn():
    """Open a fresh DB connection per request (simple, correct for SQLite)."""
    return init_db(_DB_PATH)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/alerts", response_model=list[Alert], summary="List all alerts")
def list_alerts():
    conn = _get_conn()
    try:
        return get_all_alerts(conn)
    finally:
        conn.close()


@app.get("/alerts/{alert_id}", response_model=Alert, summary="Get alert by ID")
def get_alert(alert_id: int):
    conn = _get_conn()
    try:
        alert = get_alert_by_id(conn, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert
    finally:
        conn.close()


@app.get("/ips/{ip}", response_model=list[Alert], summary="Get all alerts for a given IP")
def alerts_for_ip(ip: str):
    import ipaddress
    # Validate the IP path parameter before hitting the database
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip!r}")
    conn = _get_conn()
    try:
        return get_alerts_by_ip(conn, ip)
    finally:
        conn.close()


@app.get("/stats", summary="Summary statistics")
def stats():
    conn = _get_conn()
    try:
        return get_stats(conn)
    finally:
        conn.close()


@app.post("/ingest", summary="Ingest raw log text and run detection")
async def ingest(request: Request):
    """
    Accept raw log text (UTF-8), parse, run detection, store results.
    Returns newly created alerts.
    Size limit: api_max_body_bytes from config (default 2 MB).
    """
    body_bytes = await request.body()
    if len(body_bytes) > _MAX_BODY:
        raise HTTPException(
            status_code=413,
            detail=f"Request body exceeds {_MAX_BODY} byte limit.",
        )

    try:
        raw_text = body_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not decode body: {exc}") from exc

    lines = raw_text.splitlines()
    parser = SSHAuthParser()
    events = list(parser.parse_lines(iter(lines)))

    if not events:
        return JSONResponse({"message": "No parseable events found.", "alerts": []})

    rules = load_rules()
    engine = DetectionEngine(rules)
    alerts = engine.run(events)

    conn = _get_conn()
    try:
        save_events(conn, events)
        alerts = save_alerts(conn, alerts)
    finally:
        conn.close()

    return {
        "events_parsed": len(events),
        "alerts_raised": len(alerts),
        "alerts": [a.model_dump(mode="json") for a in alerts],
    }


# ---------------------------------------------------------------------------
# Entry point (for direct execution: python -m sentinellite.api)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("sentinellite.api:app", host="127.0.0.1", port=8000, reload=False)
