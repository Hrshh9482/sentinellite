"""
models.py — Pydantic data models for SentinelLite.

Why Pydantic? Strict validation at the boundary means bad data never reaches
detection or storage. We reject, never silently fix.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, field_validator, model_validator


# ---------------------------------------------------------------------------
# Event — one parsed log line
# ---------------------------------------------------------------------------

# Actions we recognise from SSH logs
ActionType = Literal[
    "failed_password",
    "invalid_user",
    "accepted_password",
    "sudo",
    "session_opened",
    "unknown",
]

OutcomeType = Literal["success", "failure", "unknown"]


class Event(BaseModel):
    """A single normalised log event."""

    # ISO timestamp; syslog lines without a year get the assumed year injected
    # by the parser before model construction.
    timestamp: datetime

    # Validated IPv4 or IPv6 address string; "unknown" for lines with no IP.
    source_ip: str

    user: str  # username extracted from log line; "unknown" if absent
    action: ActionType
    outcome: OutcomeType
    raw: str  # original log line — kept for evidence, never persisted in full

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        # Allow the sentinel value "unknown" for lines that genuinely have no IP
        # (e.g. sudo lines that record a username only).
        if v == "unknown":
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {v!r}") from exc
        return v

    @field_validator("raw")
    @classmethod
    def truncate_raw(cls, v: str) -> str:
        # Cap raw storage at 512 chars to bound memory; evidence stays readable.
        return v[:512]


# ---------------------------------------------------------------------------
# Alert — fired by the detection engine
# ---------------------------------------------------------------------------

SeverityType = Literal["low", "medium", "high", "critical"]


class Alert(BaseModel):
    """An alert raised by a detection rule."""

    # Unique identifier assigned by storage layer (None before persistence).
    id: Optional[int] = None

    rule_id: str          # e.g. "brute_force"
    severity: SeverityType
    mitre_id: str         # e.g. "T1110.001"

    source_ip: str
    user: str             # primary targeted user (or "multiple" for spraying)

    count: int            # number of events that triggered this alert
    window_minutes: int   # detection window used

    first_seen: datetime
    last_seen: datetime

    # Evidence: up to 10 raw lines so the alert is self-contained for reporting.
    # We cap at 10 to avoid bloating storage with full log content.
    evidence: list[str] = []

    # 0–100 score; formula documented in README.
    risk_score: int

    @field_validator("risk_score")
    @classmethod
    def clamp_score(cls, v: int) -> int:
        return max(0, min(100, v))

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        if v in ("unknown", "multiple"):
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {v!r}") from exc
        return v

    @field_validator("evidence")
    @classmethod
    def cap_evidence(cls, v: list[str]) -> list[str]:
        # Keep at most 10 lines; truncate each to 512 chars.
        return [line[:512] for line in v[:10]]

    @model_validator(mode="after")
    def check_times(self) -> "Alert":
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen must be <= last_seen")
        return self
