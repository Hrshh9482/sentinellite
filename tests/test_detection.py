"""
test_detection.py — Each rule fires and does NOT false-fire.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sentinellite.detection.engine import DetectionEngine, load_rules
from sentinellite.models import Event

_YEAR = 2024
_BASE = datetime(_YEAR, 6, 15, 10, 0, 0, tzinfo=timezone.utc)

# Load real rules.yaml so thresholds are accurate
_RULES = load_rules()


def _ev(offset_s: int, ip: str, user: str, action: str, outcome: str) -> Event:
    return Event(
        timestamp=_BASE + timedelta(seconds=offset_s),
        source_ip=ip,
        user=user,
        action=action,
        outcome=outcome,
        raw=f"fake raw line for {action} from {ip} user {user}",
    )


# ---- Brute force -------------------------------------------------------

def test_brute_force_fires():
    """10 failures from one IP in 10 min -> alert."""
    events = [_ev(i * 30, "1.2.3.4", "root", "failed_password", "failure") for i in range(10)]
    engine = DetectionEngine(_RULES)
    alerts = engine.run(events)
    bf = [a for a in alerts if a.rule_id == "brute_force"]
    assert len(bf) >= 1
    assert bf[0].source_ip == "1.2.3.4"
    assert bf[0].mitre_id == "T1110.001"


def test_brute_force_does_not_false_fire():
    """Only 5 failures — below threshold of 10 -> no brute force alert."""
    events = [_ev(i * 30, "1.2.3.4", "root", "failed_password", "failure") for i in range(5)]
    engine = DetectionEngine(_RULES)
    alerts = engine.run(events)
    bf = [a for a in alerts if a.rule_id == "brute_force"]
    assert bf == []


def test_brute_force_window_respected():
    """10 failures but spread over 20 minutes -> should NOT fire (window is 10 min)."""
    events = [_ev(i * 120, "1.2.3.4", "root", "failed_password", "failure") for i in range(10)]
    engine = DetectionEngine(_RULES)
    alerts = engine.run(events)
    bf = [a for a in alerts if a.rule_id == "brute_force"]
    assert bf == []


# ---- Password spraying --------------------------------------------------

def test_password_spraying_fires():
    """One IP, 5+ failures, 3+ distinct users -> spraying alert."""
    users = ["alice", "bob", "carol", "dave", "eve"]
    events = [_ev(i * 20, "10.10.10.1", users[i], "invalid_user", "failure") for i in range(5)]
    engine = DetectionEngine(_RULES)
    alerts = engine.run(events)
    spray = [a for a in alerts if a.rule_id == "password_spraying"]
    assert len(spray) >= 1
    assert spray[0].mitre_id == "T1110.003"


def test_password_spraying_same_user_no_fire():
    """One IP, many failures, but same user -> brute force, NOT spray."""
    events = [_ev(i * 20, "10.10.10.1", "root", "failed_password", "failure") for i in range(10)]
    engine = DetectionEngine(_RULES)
    alerts = engine.run(events)
    spray = [a for a in alerts if a.rule_id == "password_spraying"]
    assert spray == []


# ---- Credential stuffing ------------------------------------------------

def test_credential_stuffing_fires():
    """5+ distinct IPs all fail against same user -> stuffing alert."""
    ips = [f"5.5.5.{i}" for i in range(1, 8)]
    events = [_ev(i * 15, ips[i], "alice", "failed_password", "failure") for i in range(7)]
    engine = DetectionEngine(_RULES)
    alerts = engine.run(events)
    stuffing = [a for a in alerts if a.rule_id == "credential_stuffing"]
    assert len(stuffing) >= 1
    assert stuffing[0].mitre_id == "T1110.004"
    assert stuffing[0].user == "alice"


def test_credential_stuffing_single_ip_no_fire():
    """All failures from same IP -> not stuffing."""
    events = [_ev(i * 15, "5.5.5.1", "alice", "failed_password", "failure") for i in range(10)]
    engine = DetectionEngine(_RULES)
    alerts = engine.run(events)
    stuffing = [a for a in alerts if a.rule_id == "credential_stuffing"]
    assert stuffing == []


# ---- Success after failure ----------------------------------------------

def test_success_after_failure_fires():
    """3+ failures then a success from same IP -> T1078 alert."""
    events = [_ev(i * 30, "9.9.9.9", "dave", "failed_password", "failure") for i in range(5)]
    events.append(_ev(200, "9.9.9.9", "dave", "accepted_password", "success"))
    engine = DetectionEngine(_RULES)
    alerts = engine.run(events)
    saf = [a for a in alerts if a.rule_id == "success_after_failure"]
    assert len(saf) >= 1
    assert saf[0].mitre_id == "T1078"
    assert saf[0].source_ip == "9.9.9.9"


def test_success_without_prior_failures_no_fire():
    """Clean login with no prior failures -> no alert."""
    events = [_ev(0, "9.9.9.9", "dave", "accepted_password", "success")]
    engine = DetectionEngine(_RULES)
    alerts = engine.run(events)
    saf = [a for a in alerts if a.rule_id == "success_after_failure"]
    assert saf == []


# ---- Privilege abuse ----------------------------------------------------

def test_privilege_abuse_fires():
    """3+ sudo events from same user -> T1548.003 alert."""
    events = [_ev(i * 60, "unknown", "bob", "sudo", "unknown") for i in range(3)]
    engine = DetectionEngine(_RULES)
    alerts = engine.run(events)
    priv = [a for a in alerts if a.rule_id == "privilege_abuse"]
    assert len(priv) >= 1
    assert priv[0].mitre_id == "T1548.003"
    assert priv[0].user == "bob"


def test_privilege_abuse_below_threshold():
    events = [_ev(i * 60, "unknown", "bob", "sudo", "unknown") for i in range(2)]
    engine = DetectionEngine(_RULES)
    alerts = engine.run(events)
    priv = [a for a in alerts if a.rule_id == "privilege_abuse"]
    assert priv == []


# ---- Deduplication ------------------------------------------------------

def test_deduplication_same_rule_ip():
    """
    20 failures from same IP should produce only ONE brute_force alert
    (not one per failure after threshold).
    """
    events = [_ev(i * 10, "7.7.7.7", "root", "failed_password", "failure") for i in range(20)]
    engine = DetectionEngine(_RULES)
    alerts = engine.run(events)
    bf = [a for a in alerts if a.rule_id == "brute_force" and a.source_ip == "7.7.7.7"]
    assert len(bf) == 1


# ---- Risk score ---------------------------------------------------------

def test_risk_score_bounds():
    events = [_ev(i * 30, "1.2.3.4", "root", "failed_password", "failure") for i in range(10)]
    engine = DetectionEngine(_RULES)
    alerts = engine.run(events)
    for a in alerts:
        assert 0 <= a.risk_score <= 100
