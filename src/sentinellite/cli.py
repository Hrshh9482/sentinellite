"""
cli.py â€” Command-line interface for SentinelLite.

Usage:
  python -m sentinellite.cli --file path/to/auth.log [options]

Exit codes:
  0 = completed, no critical alerts
  1 = completed, critical alerts found
  2 = usage / input error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from sentinellite.detection.engine import DetectionEngine, load_rules
from sentinellite.models import Alert
from sentinellite.parsers.ssh_auth import SSHAuthParser
from sentinellite.report import generate_report
from sentinellite.storage import get_stats, init_db, save_alerts, save_events

# Max file size: 100 MB (configurable via config.yaml but hardcoded as fallback)
_MAX_FILE_BYTES = 100 * 1024 * 1024


def _load_config(project_root: Path) -> dict:
    cfg_path = project_root / "config.yaml"
    if cfg_path.exists():
        with cfg_path.open(encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {}


def _print_table(alerts: list[Alert]) -> None:
    """Simple fixed-width table output â€” no external tabulate dependency."""
    if not alerts:
        print("No alerts detected.")
        return

    header = (
        f"{'ID':<5} {'Severity':<10} {'Rule':<25} {'MITRE':<12} "
        f"{'IP':<18} {'User':<15} {'Risk':>5}"
    )
    print(header)
    print("-" * len(header))
    for a in alerts:
        print(
            f"{str(a.id or '-'):<5} {a.severity:<10} {a.rule_id:<25} "
            f"{a.mitre_id:<12} {a.source_ip:<18} {a.user:<15} {a.risk_score:>5}"
        )


def _dry_run_blocker(alerts: list[Alert]) -> None:
    """
    For high/critical alerts, print the netsh command that WOULD block the IP.
    We never execute it â€” no subprocess, no elevation required.
    """
    high_ips = {
        a.source_ip
        for a in alerts
        if a.severity in ("high", "critical") and a.source_ip not in ("unknown", "multiple")
    }
    if not high_ips:
        return

    print("\n[DRY-RUN BLOCKER] The following firewall commands would block high-severity IPs.")
    print("Review and run manually in an elevated PowerShell session if desired:\n")
    for ip in sorted(high_ips):
        print(
            f"  netsh advfirewall firewall add rule "
            f'name="SentinelLite-block-{ip}" '
            f"protocol=TCP dir=in remoteip={ip} action=block"
        )
    print()


def parse_threshold_overrides(raw: list[str]) -> dict[str, int | float]:
    """
    Parse --threshold key=value pairs from CLI args.
    e.g. ["brute_force.threshold=5", "brute_force.window_minutes=5"]
    """
    overrides: dict[str, int | float] = {}
    for item in raw:
        if "=" not in item:
            print(f"[WARN] Ignoring malformed threshold override: {item!r}", file=sys.stderr)
            continue
        key, _, val_str = item.partition("=")
        try:
            val: int | float = int(val_str)
        except ValueError:
            try:
                val = float(val_str)
            except ValueError:
                print(f"[WARN] Non-numeric threshold value ignored: {item!r}", file=sys.stderr)
                continue
        overrides[key.strip()] = val
    return overrides


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinellite",
        description="SentinelLite â€” mini-SIEM log analyser",
    )
    parser.add_argument("--file", required=True, help="Path to the log file to analyse")
    parser.add_argument(
        "--format", choices=["table", "json"], default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("--report", metavar="PATH", help="Write HTML report to this path")
    parser.add_argument("--db", metavar="PATH", help="SQLite database path (optional)")
    parser.add_argument(
        "--threshold", metavar="KEY=VAL", action="append", default=[],
        help="Override a rule threshold, e.g. brute_force.threshold=5 (repeatable)",
    )
    parser.add_argument(
        "--year", type=int, default=None,
        help="Assumed year for syslog timestamps (default: current year)",
    )

    args = parser.parse_args(argv)

    # ---- Validate input file -------------------------------------------
    log_path = Path(args.file)
    if not log_path.exists():
        print(f"ERROR: File not found: {log_path}", file=sys.stderr)
        return 2
    if not log_path.is_file():
        print(f"ERROR: Not a file: {log_path}", file=sys.stderr)
        return 2
    if log_path.stat().st_size == 0:
        print(f"ERROR: File is empty: {log_path}", file=sys.stderr)
        return 2
    if log_path.stat().st_size > _MAX_FILE_BYTES:
        print("ERROR: File exceeds 100 MB size limit.", file=sys.stderr)
        return 2

    # ---- Parse --------------------------------------------------------
    ssh_parser = SSHAuthParser()
    events = list(ssh_parser.parse_file(log_path, assumed_year=args.year))

    if not events:
        print("No parseable events found in the log file.", file=sys.stderr)
        return 2

    print(f"Parsed {len(events)} events from {log_path}")

    # ---- Detect -------------------------------------------------------
    overrides = parse_threshold_overrides(args.threshold)
    rules = load_rules(overrides=overrides)
    engine = DetectionEngine(rules)
    alerts = engine.run(events)

    print(f"Detection complete: {len(alerts)} alert(s) raised.")

    # ---- Output -------------------------------------------------------
    if args.format == "json":
        print(json.dumps([a.model_dump(mode="json") for a in alerts], indent=2, default=str))
    else:
        _print_table(alerts)

    # ---- Dry-run blocker ----------------------------------------------
    _dry_run_blocker(alerts)

    # ---- Database storage --------------------------------------------
    if args.db:
        db_path = Path(args.db)
        conn = init_db(db_path)
        save_events(conn, events)
        alerts = save_alerts(conn, alerts)
        stats = get_stats(conn)
        conn.close()
        print(f"\nDatabase: {db_path}")
        print(f"  Events stored : {stats['total_events']}")
        print(f"  Alerts stored : {stats['total_alerts']}")

    # ---- HTML report --------------------------------------------------
    if args.report:
        report_path = Path(args.report)
        generate_report(alerts, report_path)
        print(f"HTML report written to: {report_path}")

    # ---- Exit code ----------------------------------------------------
    critical_count = sum(1 for a in alerts if a.severity == "critical")
    if critical_count:
        print(f"\n[!] {critical_count} critical alert(s) found.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
