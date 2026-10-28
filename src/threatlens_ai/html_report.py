
import html
import json
from pathlib import Path


def export_html_report(
    report: dict,
    output_path: str = "security_report.html",
) -> str:
    """Export a structured security report to a standalone HTML file."""

    summary = report.get("summary", {})
    report_type = report.get("report_type", "security_report")
    title = "ThreatLens AI Security Report"
    generated_at = report.get(
        "generated_at_utc",
        report.get("checked_at_utc", "Not provided"),
    )
    source_file = report.get("file_path", "Not provided")

    # Build summary cards.
    summary_cards = ""

    for label, key in [
        ("Total Log Lines", "total_lines"),
        ("Failed Logins", "failed_login_count"),
        ("Warnings", "warning_count"),
        ("Errors", "error_count"),
        ("Unique Source IPs", "unique_source_ips"),
        ("Suspicious Events", "suspicious_event_count"),
    ]:
        value = html.escape(str(summary.get(key, 0)))
        safe_label = html.escape(label)

        summary_cards += f"""
        <div class="card">
            <span class="card-label">{safe_label}</span>
            <strong>{value}</strong>
        </div>
        """

    # Build rows for repeated failed-login IPs.
    # Support both current analyzer fields and legacy field names.
    repeated_ips = report.get("repeated_failed_login_ips", [])
    repeated_ip_rows = ""

    for item in repeated_ips:
        if isinstance(item, dict):
            ip_value = item.get(
                "ip_address",
                item.get("ip", "Unknown"),
            )
            count_value = item.get(
                "failed_login_count",
                item.get("count", "Unknown"),
            )
            severity_value = item.get("severity", "Unknown")

            ip = html.escape(str(ip_value))
            count = html.escape(str(count_value))
            severity = html.escape(str(severity_value))

            repeated_ip_rows += f"""
            <tr>
                <td>{ip}</td>
                <td>{count}</td>
                <td>{severity}</td>
            </tr>
            """
        else:
            repeated_ip_rows += f"""
            <tr>
                <td>{html.escape(str(item))}</td>
                <td>Not provided</td>
                <td>Not provided</td>
            </tr>
            """

    if not repeated_ip_rows:
        repeated_ip_rows = (
            '<tr><td colspan="3">'
            "No repeated failed-login IPs reported."
            "</td></tr>"
        )

    # Build rows for suspicious events.
    events = report.get("suspicious_events", [])
    event_rows = ""

    for event in events:
        if not isinstance(event, dict):
            continue

        line_number = html.escape(str(event.get("line_number", "—")))
        event_type = html.escape(str(event.get("event_type", "Unknown")))
        message = html.escape(
            str(event.get("message", event.get("line", "—")))
        )

        event_rows += f"""
        <tr>
            <td>{line_number}</td>
            <td>{event_type}</td>
            <td class="message">{message}</td>
        </tr>
        """

    if not event_rows:
        event_rows = (
            '<tr><td colspan="3">'
            "No suspicious events reported."
            "</td></tr>"
        )

    # Escape report metadata before inserting it into HTML.
    safe_report_type = html.escape(str(report_type))
    safe_generated_at = html.escape(str(generated_at))
    safe_source_file = html.escape(str(source_file))

    # Include a safely escaped JSON view of the complete report.
    safe_json = html.escape(
        json.dumps(report, indent=4, ensure_ascii=False)
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 1100px;
            margin: 30px auto;
            padding: 20px;
            color: #202938;
            background: #f3f5f8;
        }}
        header {{
            background: #17365d;
            color: white;
            padding: 24px;
            border-radius: 10px;
        }}
        header h1 {{ margin-top: 0; }}
        .metadata {{
            overflow-wrap: anywhere;
            line-height: 1.7;
        }}
        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 14px;
            margin: 22px 0;
        }}
        .card {{
            background: white;
            padding: 18px;
            border-radius: 8px;
            border: 1px solid #dce2ea;
        }}
        .card-label {{
            display: block;
            color: #526174;
            margin-bottom: 10px;
        }}
        .card strong {{
            font-size: 1.8rem;
        }}
        section {{
            background: white;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            border: 1px solid #dce2ea;
        }}
        .table-wrap {{ overflow-x: auto; }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            text-align: left;
            padding: 11px;
            border-bottom: 1px solid #e1e6ed;
            vertical-align: top;
        }}
        th {{ background: #edf1f6; }}
        .message {{ overflow-wrap: anywhere; }}
        details {{ margin-top: 20px; }}
        pre {{
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            background: #f7f8fa;
            padding: 16px;
            border-radius: 6px;
            overflow-x: auto;
        }}
        footer {{
            color: #526174;
            font-size: 0.9rem;
            margin-top: 25px;
        }}
    </style>
</head>
<body>
    <header>
        <h1>ThreatLens AI</h1>
        <p>Security Investigation Report</p>
        <div class="metadata">
            <div><strong>Report type:</strong> {safe_report_type}</div>
            <div><strong>Generated at (UTC):</strong> {safe_generated_at}</div>
            <div><strong>Source file:</strong> {safe_source_file}</div>
        </div>
    </header>

    <section>
        <h2>Analysis Summary</h2>
        <div class="cards">{summary_cards}</div>
    </section>

    <section>
        <h2>Repeated Failed-Login IPs</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Source IP</th>
                        <th>Failed Logins</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>{repeated_ip_rows}</tbody>
            </table>
        </div>
    </section>

    <section>
        <h2>Suspicious Events</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Line</th>
                        <th>Event Type</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>{event_rows}</tbody>
            </table>
        </div>
    </section>

    <section>
        <details>
            <summary>View complete report data (JSON)</summary>
            <pre>{safe_json}</pre>
        </details>
    </section>

    <footer>
        This report summarizes tool-generated findings. Verify important
        findings against the original logs and other available evidence.
    </footer>
</body>
</html>
"""

    # Prevent the HTML report from overwriting its source security log.
    report_file = Path(output_path)
    report_destination = report_file.resolve()
    source_path = report.get("file_path")

    if (
        report.get("report_type") == "security_log_analysis"
        and source_path is not None
    ):
        report_source = Path(source_path).resolve()

        if report_source == report_destination:
            raise ValueError(
                "The HTML report output path must not overwrite "
                "the source log file."
            )

    report_file.write_text(html_content, encoding="utf-8")

    return str(report_file.resolve())
