"""
report.py — Self-contained HTML report generator.

Why single-file with no CDN? The report must be viewable offline and must not
load external resources (which could leak that a scan occurred). All CSS and
JS are inlined.

We use textContent everywhere — never innerHTML with alert data — to ensure
XSS is impossible even if an attacker controlled log content.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sentinellite.models import Alert

# Severity -> CSS colour class
_SEV_COLOR = {
    "low": "#6c757d",
    "medium": "#fd7e14",
    "high": "#dc3545",
    "critical": "#6f0f1e",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _escape(text: str) -> str:
    """HTML-escape a string for safe insertion into HTML attributes/text."""
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
    )


def generate_report(alerts: list[Alert], output_path: Path) -> None:
    """Write a single-file HTML report to output_path."""
    sorted_alerts = sorted(alerts, key=lambda a: _SEVERITY_ORDER.get(a.severity, 9))

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in alerts:
        severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1

    # Top attackers by alert count
    ip_counts: dict[str, int] = {}
    for a in alerts:
        if a.source_ip not in ("unknown", "multiple"):
            ip_counts[a.source_ip] = ip_counts.get(a.source_ip, 0) + 1
    top_attackers = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]

    # Targeted usernames
    user_counts: dict[str, int] = {}
    for a in alerts:
        if a.user not in ("unknown", "multiple"):
            user_counts[a.user] = user_counts.get(a.user, 0) + 1
    top_users = sorted(user_counts.items(), key=lambda x: -x[1])[:10]

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ---- Build HTML sections -------------------------------------------

    def card(label: str, value: str, color: str) -> str:
        return (
            f'<div class="card" style="border-left:4px solid {color}">'
            f'<div class="card-value">{_escape(value)}</div>'
            f'<div class="card-label">{_escape(label)}</div>'
            f"</div>"
        )

    summary_cards = "".join([
        card("Total Alerts", str(len(alerts)), "#0d6efd"),
        card("Critical", str(severity_counts["critical"]), _SEV_COLOR["critical"]),
        card("High", str(severity_counts["high"]), _SEV_COLOR["high"]),
        card("Medium", str(severity_counts["medium"]), _SEV_COLOR["medium"]),
        card("Low", str(severity_counts["low"]), _SEV_COLOR["low"]),
    ])

    def attacker_rows() -> str:
        if not top_attackers:
            return "<tr><td colspan='2'>No attacker IPs recorded</td></tr>"
        return "".join(
            f"<tr><td>{_escape(ip)}</td><td>{count}</td></tr>"
            for ip, count in top_attackers
        )

    def user_rows() -> str:
        if not top_users:
            return "<tr><td colspan='2'>No targeted users recorded</td></tr>"
        return "".join(
            f"<tr><td>{_escape(u)}</td><td>{count}</td></tr>"
            for u, count in top_users
        )

    def alert_cards() -> str:
        if not sorted_alerts:
            return "<p>No alerts detected.</p>"
        parts = []
        for a in sorted_alerts:
            color = _SEV_COLOR.get(a.severity, "#6c757d")
            ev_html = "".join(
                f"<li><code>{_escape(line)}</code></li>" for line in a.evidence
            )
            parts.append(f"""
            <div class="alert-card" style="border-left:4px solid {color}">
                <div class="alert-header">
                    <span class="badge" style="background:{color}">{_escape(a.severity.upper())}</span>
                    <strong>{_escape(a.rule_id.replace("_"," ").title())}</strong>
                    <span class="mitre">{_escape(a.mitre_id)}</span>
                    <span class="risk">Risk: {a.risk_score}/100</span>
                </div>
                <dl>
                    <dt>Source IP</dt><dd>{_escape(a.source_ip)}</dd>
                    <dt>User</dt><dd>{_escape(a.user)}</dd>
                    <dt>Count</dt><dd>{a.count} events in {a.window_minutes} min window</dd>
                    <dt>First seen</dt><dd>{_escape(a.first_seen.isoformat())}</dd>
                    <dt>Last seen</dt><dd>{_escape(a.last_seen.isoformat())}</dd>
                </dl>
                <details>
                    <summary>Evidence ({len(a.evidence)} lines)</summary>
                    <ul class="evidence">{ev_html}</ul>
                </details>
            </div>""")
        return "\n".join(parts)

    # Timeline: one row per alert sorted by last_seen
    timeline_sorted = sorted(alerts, key=lambda a: a.last_seen)

    def timeline_rows() -> str:
        if not timeline_sorted:
            return "<tr><td colspan='5'>No alerts</td></tr>"
        return "".join(
            f"<tr>"
            f"<td>{_escape(a.last_seen.strftime('%H:%M:%S'))}</td>"
            f"<td><span style='color:{_SEV_COLOR.get(a.severity,'#000')}'>"
            f"{_escape(a.severity)}</span></td>"
            f"<td>{_escape(a.rule_id)}</td>"
            f"<td>{_escape(a.source_ip)}</td>"
            f"<td>{_escape(a.user)}</td>"
            f"</tr>"
            for a in timeline_sorted
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SentinelLite Report — {generated_at}</title>
<style>
  body{{font-family:system-ui,sans-serif;margin:0;padding:1rem 2rem;background:#f8f9fa;color:#212529}}
  h1{{color:#0d1b2a}}h2{{margin-top:2rem;border-bottom:2px solid #dee2e6;padding-bottom:.3rem}}
  .cards{{display:flex;flex-wrap:wrap;gap:1rem;margin:1rem 0}}
  .card{{background:#fff;border-radius:6px;padding:1rem 1.5rem;min-width:120px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
  .card-value{{font-size:2rem;font-weight:700}}
  .card-label{{color:#6c757d;font-size:.85rem}}
  table{{border-collapse:collapse;width:100%;background:#fff;border-radius:6px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
  th{{background:#0d1b2a;color:#fff;padding:.6rem 1rem;text-align:left}}
  td{{padding:.5rem 1rem;border-bottom:1px solid #dee2e6}}
  tr:last-child td{{border-bottom:none}}
  .alert-card{{background:#fff;border-radius:6px;padding:1rem 1.5rem;margin:.75rem 0;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
  .alert-header{{display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem;flex-wrap:wrap}}
  .badge{{color:#fff;padding:.2rem .6rem;border-radius:4px;font-size:.8rem;font-weight:700}}
  .mitre{{font-family:monospace;background:#e9ecef;padding:.1rem .4rem;border-radius:3px;font-size:.85rem}}
  .risk{{margin-left:auto;font-size:.85rem;color:#6c757d}}
  dl{{display:grid;grid-template-columns:140px 1fr;gap:.2rem .5rem;margin:.5rem 0}}
  dt{{font-weight:600;color:#495057}}
  details summary{{cursor:pointer;color:#0d6efd;font-size:.9rem}}
  ul.evidence{{font-size:.8rem;background:#f8f9fa;padding:.5rem 1rem;border-radius:4px;max-height:200px;overflow-y:auto}}
  ul.evidence li{{margin:.2rem 0;word-break:break-all}}
  footer{{margin-top:3rem;color:#6c757d;font-size:.8rem;border-top:1px solid #dee2e6;padding-top:.5rem}}
</style>
</head>
<body>
<h1>&#128737; SentinelLite Security Report</h1>
<p>Generated: {_escape(generated_at)}</p>

<h2>Summary</h2>
<div class="cards">{summary_cards}</div>

<h2>Top Attackers</h2>
<table>
  <tr><th>Source IP</th><th>Alert Count</th></tr>
  {attacker_rows()}
</table>

<h2>Targeted Usernames</h2>
<table>
  <tr><th>Username</th><th>Alert Count</th></tr>
  {user_rows()}
</table>

<h2>Alert Timeline</h2>
<table>
  <tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source IP</th><th>User</th></tr>
  {timeline_rows()}
</table>

<h2>Alert Details</h2>
{alert_cards()}

<footer>
  SentinelLite — portfolio mini-SIEM. Results indicate suspicious signals only.
  "No alerts" means no strong indicators were found, not that the system is guaranteed safe.
</footer>
</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")
