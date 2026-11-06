"""
ssh_auth.py — Parser for OpenSSH auth.log / secure log format.

Syslog timestamp format: "Mon DD HH:MM:SS" (no year).
We inject the assumed year before constructing the Event so the model
receives a complete ISO timestamp and does not need to know about syslog quirks.

Why stream line-by-line? Log files can be huge; we never load the whole file
into memory.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import datetime, timezone

from pydantic import ValidationError

from sentinellite.models import ActionType, Event, OutcomeType
from sentinellite.parsers.base import BaseParser

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Syslog prefix: "Jan  1 00:00:00 hostname sshd[pid]:"
# We capture the timestamp and ignore hostname/pid — not needed for detection.
_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+\S+:\s+"
)

# IP address — strict: only valid IPv4/IPv6 characters; full validation done
# by the Pydantic model so we just extract a candidate here.
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]{2,39})\b")

# Line-level patterns (checked in order; first match wins)
_PATTERNS: list[tuple[re.Pattern[str], ActionType, OutcomeType, str | None, str | None]] = [
    # Failed password for invalid user bob from 1.2.3.4 port 22 ssh2
    (
        re.compile(r"Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+)"),
        "invalid_user", "failure", "user", "ip",
    ),
    # Failed password for bob from 1.2.3.4 port 22 ssh2
    (
        re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>\S+)"),
        "failed_password", "failure", "user", "ip",
    ),
    # Invalid user bob from 1.2.3.4 port 22
    (
        re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"),
        "invalid_user", "failure", "user", "ip",
    ),
    # Accepted password for bob from 1.2.3.4 port 22 ssh2
    (
        re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)"),
        "accepted_password", "success", "user", "ip",
    ),
    # sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash
    (
        re.compile(r"sudo:\s+(?P<user>\S+)\s+:"),
        "sudo", "unknown", "user", None,
    ),
    # pam_unix(sshd:session): session opened for user bob by (uid=0)
    (
        re.compile(r"session opened for user (?P<user>\S+)"),
        "session_opened", "success", "user", None,
    ),
]

# Month name -> number lookup (syslog uses abbreviated English month names)
_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4,
    "may": 5, "jun": 6, "jul": 7, "aug": 8,
    "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


def _parse_syslog_timestamp(month: str, day: str, time_str: str, year: int) -> datetime | None:
    """Convert syslog date parts to a timezone-aware datetime (UTC assumed)."""
    month_num = _MONTHS.get(month.lower())
    if month_num is None:
        return None
    try:
        h, m, s = (int(x) for x in time_str.split(":"))
        return datetime(year, month_num, int(day), h, m, s, tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


class SSHAuthParser(BaseParser):
    """Parse OpenSSH auth.log lines into Events."""

    def parse_lines(self, lines: Iterator[str], assumed_year: int | None = None) -> Iterator[Event]:
        year = assumed_year if assumed_year is not None else datetime.now().year

        for raw_line in lines:
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue  # skip blank lines silently

            # Match syslog prefix to extract timestamp
            prefix_match = _SYSLOG_PREFIX.match(line)
            if prefix_match is None:
                continue  # not a syslog line we understand

            ts = _parse_syslog_timestamp(
                prefix_match.group("month"),
                prefix_match.group("day"),
                prefix_match.group("time"),
                year,
            )
            if ts is None:
                continue

            # Remainder of the line after the prefix
            body = line[prefix_match.end():]

            # Try each pattern
            action: ActionType = "unknown"
            outcome: OutcomeType = "unknown"
            user = "unknown"
            ip = "unknown"

            for pattern, act, out, user_group, ip_group in _PATTERNS:
                m = pattern.search(body)
                if m:
                    action = act
                    outcome = out
                    if user_group:
                        user = m.group(user_group)
                    if ip_group:
                        ip = m.group(ip_group)
                    break

            # For sudo/session lines that have no IP in the pattern,
            # try to find one anywhere in the body (best-effort).
            if ip == "unknown":
                ip_match = _IP_RE.search(body)
                if ip_match:
                    ip = ip_match.group(1)

            # Build and validate the Event; skip on validation error so malformed
            # lines never propagate.
            try:
                yield Event(
                    timestamp=ts,
                    source_ip=ip,
                    user=user,
                    action=action,
                    outcome=outcome,
                    raw=line,
                )
            except (ValidationError, ValueError):
                # Invalid IP or other field — skip silently per spec
                continue
