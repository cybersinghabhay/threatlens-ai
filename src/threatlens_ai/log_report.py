
import json
from datetime import datetime, timezone
from pathlib import Path

from threatlens_ai.log_analyzer import analyze_log_file


def generate_log_report(log_path: str) -> dict:
    """Generate a structured security log analysis report."""

    analysis = analyze_log_file(log_path)

    return {
        "report_type": "security_log_analysis",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "file_path": analysis["file_path"],
        "summary": {
            "total_lines": analysis["total_lines"],
            "failed_login_count": analysis["failed_login_count"],
            "warning_count": analysis["warning_count"],
            "error_count": analysis["error_count"],
            "unique_source_ips": len(analysis["source_ip_counts"]),
            "suspicious_event_count": len(
                analysis["suspicious_events"]
            ),
        },
        "source_ip_counts": analysis["source_ip_counts"],
        "suspicious_events": analysis["suspicious_events"],
    }


def export_log_report(
    report: dict,
    output_path: str = "security_log_report.json",
) -> str:
    """Export a security log report to a JSON file."""

    report_file = Path(output_path)
    report_destination = report_file.resolve()

    source_path = report.get("file_path")

    if source_path is not None:
        report_source = Path(source_path).resolve()

        if report_source == report_destination:
            raise ValueError(
                "The report output path must not overwrite "
                "the source log file."
            )

    report_file.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )

    return str(report_file.resolve())
