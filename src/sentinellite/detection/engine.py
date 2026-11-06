"""
engine.py — Rule-driven detection engine with per-IP sliding windows.

Design: we do a single pass over events sorted by timestamp, maintaining
sliding windows per (rule, key) using a deque. This is O(n) per rule and
avoids loading all events into RAM twice.

Deduplication: once an alert fires for (rule_id, source_ip) within the
detection window, we suppress re-firing until the window rolls over.
This prevents alert storms from a single prolonged attack.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from sentinellite.models import Alert, Event

# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

_DEFAULT_RULES_PATH = Path(__file__).parent / "rules.yaml"


def load_rules(path: Path | None = None, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Load rules.yaml and apply any CLI-supplied threshold overrides.
    Overrides format: {"brute_force.threshold": 5, ...}
    """
    rules_path = path or _DEFAULT_RULES_PATH
    with rules_path.open(encoding="utf-8") as fh:
        rules: dict[str, Any] = yaml.safe_load(fh)

    if overrides:
        for key, value in overrides.items():
            # key format: "rule_name.field", e.g. "brute_force.threshold"
            parts = key.split(".", 1)
            if len(parts) == 2 and parts[0] in rules:
                rules[parts[0]][parts[1]] = value

    return rules


# ---------------------------------------------------------------------------
# Risk score formula
# ---------------------------------------------------------------------------
# score = base_severity + volume_bonus + recency_bonus
#
# base_severity:  low=10, medium=30, high=60, critical=85
# volume_bonus:   min(20, count // threshold * 5)   — scales with how many
#                 times over the threshold the attack is
# recency_bonus:  10 if last_seen within last 5 min (attack is ongoing), else 0
#
# Capped at 100 by the Alert validator.

_SEVERITY_BASE = {"low": 10, "medium": 30, "high": 60, "critical": 85}


def _risk_score(severity: str, count: int, threshold: int, last_seen: datetime) -> int:
    base = _SEVERITY_BASE.get(severity, 30)
    volume_bonus = min(20, (count // max(threshold, 1)) * 5)
    now = datetime.now(tz=timezone.utc)
    recency_bonus = 10 if (now - last_seen).total_seconds() < 300 else 0
    return base + volume_bonus + recency_bonus


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

class DetectionEngine:
    def __init__(self, rules: dict[str, Any]):
        self.rules = rules

    def run(self, events: list[Event]) -> list[Alert]:
        """Run all enabled rules over a sorted event list and return alerts."""
        # Sort events by timestamp once; all rules reuse the same order.
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        alerts: list[Alert] = []

        if self.rules.get("brute_force", {}).get("enabled"):
            alerts.extend(self._brute_force(sorted_events))

        if self.rules.get("password_spraying", {}).get("enabled"):
            alerts.extend(self._password_spraying(sorted_events))

        if self.rules.get("credential_stuffing", {}).get("enabled"):
            alerts.extend(self._credential_stuffing(sorted_events))

        if self.rules.get("success_after_failure", {}).get("enabled"):
            alerts.extend(self._success_after_failure(sorted_events))

        if self.rules.get("privilege_abuse", {}).get("enabled"):
            alerts.extend(self._privilege_abuse(sorted_events))

        return alerts

    # ------------------------------------------------------------------
    # Rule implementations
    # ------------------------------------------------------------------

    def _brute_force(self, events: list[Event]) -> list[Alert]:
        """
        T1110.001 — N failures from ONE IP in M minutes.
        We use a per-IP deque to maintain the sliding window.
        """
        cfg = self.rules["brute_force"]
        window = timedelta(minutes=cfg["window_minutes"])
        threshold = cfg["threshold"]
        severity = cfg["severity"]
        mitre_id = cfg["mitre_id"]

        # ip -> deque of (timestamp, raw_line) for failure events
        windows: dict[str, deque] = defaultdict(deque)
        fired: dict[str, datetime] = {}  # ip -> last alert time for dedup
        alerts: list[Alert] = []

        failure_actions = {"failed_password", "invalid_user"}

        for ev in events:
            if ev.action not in failure_actions or ev.source_ip == "unknown":
                continue

            dq = windows[ev.source_ip]
            dq.append((ev.timestamp, ev.raw))

            # Evict events outside the window
            while dq and (ev.timestamp - dq[0][0]) > window:
                dq.popleft()

            count = len(dq)
            if count < threshold:
                continue

            # Deduplication: don't re-fire within the same window
            if ev.source_ip in fired and (ev.timestamp - fired[ev.source_ip]) <= window:
                continue

            fired[ev.source_ip] = ev.timestamp
            first_seen = dq[0][0]
            evidence = [r for _, r in dq]

            alerts.append(Alert(
                rule_id="brute_force",
                severity=severity,
                mitre_id=mitre_id,
                source_ip=ev.source_ip,
                user=ev.user,
                count=count,
                window_minutes=cfg["window_minutes"],
                first_seen=first_seen,
                last_seen=ev.timestamp,
                evidence=evidence,
                risk_score=_risk_score(severity, count, threshold, ev.timestamp),
            ))

        return alerts

    def _password_spraying(self, events: list[Event]) -> list[Alert]:
        """
        T1110.003 — One IP targets >= threshold_users distinct users.
        """
        cfg = self.rules["password_spraying"]
        window = timedelta(minutes=cfg["window_minutes"])
        threshold = cfg["threshold"]
        threshold_users = cfg["threshold_users"]
        severity = cfg["severity"]
        mitre_id = cfg["mitre_id"]

        failure_actions = {"failed_password", "invalid_user"}

        # ip -> deque of (timestamp, user, raw)
        windows: dict[str, deque] = defaultdict(deque)
        fired: dict[str, datetime] = {}
        alerts: list[Alert] = []

        for ev in events:
            if ev.action not in failure_actions or ev.source_ip == "unknown":
                continue

            dq = windows[ev.source_ip]
            dq.append((ev.timestamp, ev.user, ev.raw))

            while dq and (ev.timestamp - dq[0][0]) > window:
                dq.popleft()

            users_in_window = {u for _, u, _ in dq}
            count = len(dq)

            if count < threshold or len(users_in_window) < threshold_users:
                continue

            if ev.source_ip in fired and (ev.timestamp - fired[ev.source_ip]) <= window:
                continue

            fired[ev.source_ip] = ev.timestamp
            first_seen = dq[0][0]
            evidence = [r for _, _, r in dq]

            alerts.append(Alert(
                rule_id="password_spraying",
                severity=severity,
                mitre_id=mitre_id,
                source_ip=ev.source_ip,
                user="multiple",
                count=count,
                window_minutes=cfg["window_minutes"],
                first_seen=first_seen,
                last_seen=ev.timestamp,
                evidence=evidence,
                risk_score=_risk_score(severity, count, threshold, ev.timestamp),
            ))

        return alerts

    def _credential_stuffing(self, events: list[Event]) -> list[Alert]:
        """
        T1110.004 — Many distinct IPs targeting ONE user.
        We group by user and maintain per-user sliding windows of (ip, raw).
        """
        cfg = self.rules["credential_stuffing"]
        window = timedelta(minutes=cfg["window_minutes"])
        threshold_ips = cfg["threshold_ips"]
        severity = cfg["severity"]
        mitre_id = cfg["mitre_id"]

        failure_actions = {"failed_password", "invalid_user"}

        # user -> deque of (timestamp, ip, raw)
        windows: dict[str, deque] = defaultdict(deque)
        fired: dict[str, datetime] = {}
        alerts: list[Alert] = []

        for ev in events:
            if ev.action not in failure_actions or ev.source_ip == "unknown":
                continue
            if ev.user == "unknown":
                continue

            dq = windows[ev.user]
            dq.append((ev.timestamp, ev.source_ip, ev.raw))

            while dq and (ev.timestamp - dq[0][0]) > window:
                dq.popleft()

            ips_in_window = {ip for _, ip, _ in dq}
            count = len(dq)

            if len(ips_in_window) < threshold_ips:
                continue

            if ev.user in fired and (ev.timestamp - fired[ev.user]) <= window:
                continue

            fired[ev.user] = ev.timestamp
            first_seen = dq[0][0]
            evidence = [r for _, _, r in dq]

            alerts.append(Alert(
                rule_id="credential_stuffing",
                severity=severity,
                mitre_id=mitre_id,
                source_ip="multiple",
                user=ev.user,
                count=count,
                window_minutes=cfg["window_minutes"],
                first_seen=first_seen,
                last_seen=ev.timestamp,
                evidence=evidence,
                risk_score=_risk_score(severity, count, threshold_ips, ev.timestamp),
            ))

        return alerts

    def _success_after_failure(self, events: list[Event]) -> list[Alert]:
        """
        T1078 — IP succeeds after N prior failures in M minutes.
        This is suspicious: could mean correct password was eventually guessed.
        """
        cfg = self.rules["success_after_failure"]
        window = timedelta(minutes=cfg["window_minutes"])
        threshold = cfg["threshold"]
        severity = cfg["severity"]
        mitre_id = cfg["mitre_id"]

        failure_actions = {"failed_password", "invalid_user"}

        # ip -> deque of (timestamp, raw) for failures
        fail_windows: dict[str, deque] = defaultdict(deque)
        fired: set[str] = set()
        alerts: list[Alert] = []

        for ev in events:
            if ev.source_ip == "unknown":
                continue

            if ev.action in failure_actions and ev.outcome == "failure":
                dq = fail_windows[ev.source_ip]
                dq.append((ev.timestamp, ev.raw))
                while dq and (ev.timestamp - dq[0][0]) > window:
                    dq.popleft()

            elif ev.action == "accepted_password" and ev.outcome == "success":
                dq = fail_windows.get(ev.source_ip, deque())
                # Evict stale failures
                while dq and (ev.timestamp - dq[0][0]) > window:
                    dq.popleft()

                if len(dq) >= threshold and ev.source_ip not in fired:
                    fired.add(ev.source_ip)
                    evidence = [r for _, r in dq] + [ev.raw]
                    first_seen = dq[0][0]

                    alerts.append(Alert(
                        rule_id="success_after_failure",
                        severity=severity,
                        mitre_id=mitre_id,
                        source_ip=ev.source_ip,
                        user=ev.user,
                        count=len(dq),
                        window_minutes=cfg["window_minutes"],
                        first_seen=first_seen,
                        last_seen=ev.timestamp,
                        evidence=evidence,
                        risk_score=_risk_score(severity, len(dq), threshold, ev.timestamp),
                    ))

        return alerts

    def _privilege_abuse(self, events: list[Event]) -> list[Alert]:
        """
        T1548.003 — User runs sudo >= N times in M minutes.
        We key on user (not IP) since sudo lines may lack a source IP.
        """
        cfg = self.rules["privilege_abuse"]
        window = timedelta(minutes=cfg["window_minutes"])
        threshold = cfg["threshold"]
        severity = cfg["severity"]
        mitre_id = cfg["mitre_id"]

        # user -> deque of (timestamp, ip, raw)
        windows: dict[str, deque] = defaultdict(deque)
        fired: dict[str, datetime] = {}
        alerts: list[Alert] = []

        for ev in events:
            if ev.action != "sudo":
                continue
            if ev.user == "unknown":
                continue

            dq = windows[ev.user]
            dq.append((ev.timestamp, ev.source_ip, ev.raw))

            while dq and (ev.timestamp - dq[0][0]) > window:
                dq.popleft()

            count = len(dq)
            if count < threshold:
                continue

            if ev.user in fired and (ev.timestamp - fired[ev.user]) <= window:
                continue

            fired[ev.user] = ev.timestamp
            first_seen = dq[0][0]
            # Use "unknown" if IPs are mixed or absent
            ips = {ip for _, ip, _ in dq if ip != "unknown"}
            src_ip = list(ips)[0] if len(ips) == 1 else ("multiple" if ips else "unknown")
            evidence = [r for _, _, r in dq]

            alerts.append(Alert(
                rule_id="privilege_abuse",
                severity=severity,
                mitre_id=mitre_id,
                source_ip=src_ip,
                user=ev.user,
                count=count,
                window_minutes=cfg["window_minutes"],
                first_seen=first_seen,
                last_seen=ev.timestamp,
                evidence=evidence,
                risk_score=_risk_score(severity, count, threshold, ev.timestamp),
            ))

        return alerts
