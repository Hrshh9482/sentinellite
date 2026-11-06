"""
log_simulator.py — Generate realistic sample SSH auth.log entries.

Scenarios generated:
  1. Normal traffic  — occasional legit logins from a few IPs
  2. Brute force     — one IP hammering one user
  3. Password spray  — one IP trying many usernames
  4. Cred stuffing   — many IPs all targeting the same user
  5. Success after failure — brute force that eventually succeeds

Usage:
  python tools/log_simulator.py            # writes tests/fixtures/sample_auth.log
  python tools/log_simulator.py --out /other/path.log
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Seed for reproducibility in tests
random.seed(42)

_USERS = ["alice", "bob", "carol", "dave", "root", "admin", "ubuntu", "git"]
_LEGIT_IPS = ["10.0.0.5", "10.0.0.6", "192.168.1.20"]
_ATTACKER_IP = "203.0.113.50"   # brute force / spray
_STUFFING_IPS = [f"198.51.100.{i}" for i in range(1, 12)]  # 11 IPs for cred stuffing
_VICTIM_USER = "alice"  # target of cred stuffing & success-after-failure


def _fmt(dt: datetime) -> str:
    """Format datetime as syslog timestamp (no year, abbreviated month)."""
    return dt.strftime("%b %d %H:%M:%S").replace("  ", " ")  # single-digit day padding


def _host() -> str:
    return "myserver"


def _pid() -> int:
    return random.randint(10000, 65000)


def gen_lines(base_time: datetime) -> list[str]:
    lines: list[str] = []
    t = base_time

    def add(ts: datetime, msg: str) -> None:
        lines.append(f"{_fmt(ts)} {_host()} sshd[{_pid()}]: {msg}")

    # 1. Normal traffic — spread over 30 minutes
    for _ in range(20):
        t = base_time + timedelta(seconds=random.randint(0, 1800))
        ip = random.choice(_LEGIT_IPS)
        user = random.choice(["alice", "bob", "carol"])
        add(t, f"Accepted password for {user} from {ip} port {random.randint(40000,65000)} ssh2")
        add(t + timedelta(seconds=2), f"pam_unix(sshd:session): session opened for user {user} by (uid=0)")

    # 2. Brute force — _ATTACKER_IP tries "root" 20 times in 5 minutes
    t = base_time + timedelta(minutes=5)
    for i in range(20):
        t += timedelta(seconds=random.randint(5, 20))
        add(t, f"Failed password for root from {_ATTACKER_IP} port {random.randint(40000,65000)} ssh2")

    # 3. Password spray — _ATTACKER_IP tries 8 different users (2 attempts each) in 8 minutes
    t = base_time + timedelta(minutes=15)
    spray_users = random.sample(_USERS, 8)
    for user in spray_users:
        for _ in range(2):
            t += timedelta(seconds=random.randint(10, 40))
            add(t, f"Failed password for invalid user {user} from {_ATTACKER_IP} port {random.randint(40000,65000)} ssh2")

    # 4. Credential stuffing — 11 IPs all try "alice"
    t = base_time + timedelta(minutes=30)
    for ip in _STUFFING_IPS:
        for _ in range(2):
            t += timedelta(seconds=random.randint(5, 30))
            add(t, f"Failed password for {_VICTIM_USER} from {ip} port {random.randint(40000,65000)} ssh2")

    # 5. Success after failure — one IP fails 5 times then succeeds
    t = base_time + timedelta(minutes=45)
    saf_ip = "198.51.100.99"
    for _ in range(5):
        t += timedelta(seconds=random.randint(10, 30))
        add(t, f"Failed password for dave from {saf_ip} port {random.randint(40000,65000)} ssh2")
    t += timedelta(seconds=15)
    add(t, f"Accepted password for dave from {saf_ip} port {random.randint(40000,65000)} ssh2")
    add(t + timedelta(seconds=1), "pam_unix(sshd:session): session opened for user dave by (uid=0)")

    # 6. Sudo abuse — bob runs sudo 4 times quickly
    t = base_time + timedelta(minutes=50)
    for _ in range(4):
        t += timedelta(seconds=random.randint(5, 15))
        add(t, "sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash")

    # Sort by timestamp so the file looks like a real log
    lines.sort()
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate sample SSH auth.log")
    parser.add_argument(
        "--out",
        default=str(Path(__file__).parent.parent / "tests" / "fixtures" / "sample_auth.log"),
        help="Output file path",
    )
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    base_time = datetime(2024, 6, 15, 8, 0, 0, tzinfo=timezone.utc)
    lines = gen_lines(base_time)

    with out_path.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print(f"Wrote {len(lines)} log lines to {out_path}")


if __name__ == "__main__":
    main()
