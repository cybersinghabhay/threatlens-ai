
import json
from datetime import datetime, timezone
from pathlib import Path

from threatlens_ai.log_analyzer import analyze_log_file
from threatlens_ai.finding_integration import (
    explain_repeated_failed_login,
)
from threatlens_ai.investigation_timeline import (
    sort_events_chronologically,
)
from threatlens_ai.severity_filter import (
    filter_events_by_severity,
    filter_findings_by_severity,
    validate_severity_filter,
)


def generate_log_report(
    log_path: str,
    failed_login_threshold: int = 5,
    severity: str = "all",
) -> dict:
    """Generate a structured security log analysis report."""

    # Validate the requested severity filter.
    selected_severity = validate_severity_filter(severity)

    analysis = analyze_log_file(
        log_path,
        failed_login_threshold=failed_login_threshold,
    )

    repeated_failed_login_ips = analysis[
        "repeated_failed_login_ips"
    ]

    explained_findings = explain_repeated_failed_login(
        repeated_failed_login_ips
    )

    # Preserve the complete collection of detected events.
    suspicious_events = analysis["suspicious_events"]

    # Sort all collected events chronologically.
    investigation_timeline = sort_events_chronologically(
        suspicious_events
    )

    # Create separate filtered views without modifying the evidence.
    filtered_events = filter_events_by_severity(
        suspicious_events,
        selected_severity,
    )

    filtered_findings = filter_findings_by_severity(
        explained_findings,
        selected_severity,
    )

    return {
        "report_type": "security_log_analysis",
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "file_path": analysis["file_path"],
        "severity_filter": selected_severity,
        "summary": {
            "total_lines": analysis["total_lines"],
            "failed_login_count": analysis[
                "failed_login_count"
            ],
            "warning_count": analysis["warning_count"],
            "error_count": analysis["error_count"],
            "unique_source_ips": len(
                analysis["source_ip_counts"]
            ),
            "suspicious_event_count": len(
                suspicious_events
            ),
            "filtered_event_count": len(
                filtered_events
            ),
            "repeated_failed_login_ip_count": len(
                repeated_failed_login_ips
            ),
            "filtered_finding_count": len(
                filtered_findings
            ),
            "failed_login_threshold": analysis[
                "failed_login_threshold"
            ],
        },
        "source_ip_counts": analysis["source_ip_counts"],
        "suspicious_events": suspicious_events,
        "investigation_timeline": investigation_timeline,
        "filtered_events": filtered_events,
        "repeated_failed_login_ips": repeated_failed_login_ips,
        "explained_findings": explained_findings,
        "filtered_findings": filtered_findings,
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
