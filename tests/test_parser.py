"""
test_parser.py — Parser edge cases.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sentinellite.parsers.ssh_auth import SSHAuthParser


def _parse(lines: list[str], year: int = 2024) -> list:
    parser = SSHAuthParser()
    return list(parser.parse_lines(iter(lines), assumed_year=year))


# ---- Happy path --------------------------------------------------------

def test_failed_password():
    lines = ["Jun 15 08:01:00 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"]
    events = _parse(lines)
    assert len(events) == 1
    e = events[0]
    assert e.action == "failed_password"
    assert e.outcome == "failure"
    assert e.source_ip == "1.2.3.4"
    assert e.user == "root"


def test_invalid_user():
    lines = ["Jun 15 08:02:00 host sshd[1234]: Invalid user ghost from 5.6.7.8 port 22"]
    events = _parse(lines)
    assert len(events) == 1
    assert events[0].action == "invalid_user"
    assert events[0].source_ip == "5.6.7.8"


def test_accepted_password():
    lines = ["Jun 15 09:00:00 host sshd[1234]: Accepted password for alice from 10.0.0.1 port 22 ssh2"]
    events = _parse(lines)
    assert len(events) == 1
    assert events[0].action == "accepted_password"
    assert events[0].outcome == "success"


def test_sudo_line():
    lines = ["Jun 15 09:05:00 host sshd[1234]: sudo: bob : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"]
    events = _parse(lines)
    assert len(events) == 1
    assert events[0].action == "sudo"
    assert events[0].user == "bob"


def test_session_opened():
    lines = ["Jun 15 09:01:00 host sshd[1234]: pam_unix(sshd:session): session opened for user carol by (uid=0)"]
    events = _parse(lines)
    assert len(events) == 1
    assert events[0].action == "session_opened"
    assert events[0].user == "carol"


# ---- Edge cases --------------------------------------------------------

def test_empty_input():
    """Empty input yields no events and does not crash."""
    events = _parse([])
    assert events == []


def test_blank_lines_skipped():
    events = _parse(["", "   ", "\n"])
    assert events == []


def test_malformed_line_skipped():
    """Lines that don't match the syslog prefix are silently dropped."""
    lines = [
        "this is not a syslog line",
        "Jun 15 08:01:00 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2",
    ]
    events = _parse(lines)
    assert len(events) == 1  # only the valid line


def test_invalid_ip_skipped():
    """A line with an invalid IP should be dropped, not crash."""
    lines = ["Jun 15 08:01:00 host sshd[1234]: Failed password for root from 999.999.999.999 port 22"]
    events = _parse(lines)
    assert events == []


def test_assumed_year_injected():
    lines = ["Mar  1 12:00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 22"]
    events = _parse(lines, year=2023)
    assert events[0].timestamp.year == 2023


def test_raw_truncated_at_512():
    long_line = "Jun 15 08:01:00 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2 " + "x" * 600
    events = _parse([long_line])
    assert len(events) == 1
    assert len(events[0].raw) <= 512


def test_sample_fixture_parses(tmp_path):
    """The generated sample_auth.log must parse without errors."""
    fixture = Path(__file__).parent / "fixtures" / "sample_auth.log"
    if not fixture.exists():
        pytest.skip("sample_auth.log not generated yet — run tools/log_simulator.py")
    parser = SSHAuthParser()
    events = list(parser.parse_file(fixture, assumed_year=2024))
    assert len(events) > 0
