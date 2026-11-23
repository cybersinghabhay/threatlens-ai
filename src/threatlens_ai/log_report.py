
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
from threatlens_ai.threat_context import generate_threat_context


def generate_log_report(
    log_path: str,
    failed_login_threshold: int = 5,
    severity: str = "all",
    ai_analyzer=None,
) -> dict:
    """Generate a structured security log analysis report.

    AI analysis is optional and supplements deterministic findings.
    Only minimized finding data is passed to the AI analyzer.
    """

    # Validate the requested severity filter.
    selected_severity = validate_severity_filter(severity)

    # Analyze the source security log using deterministic rules.
    analysis = analyze_log_file(
        log_path,
        failed_login_threshold=failed_login_threshold,
    )

    repeated_failed_login_ips = analysis[
        "repeated_failed_login_ips"
    ]

    # Generate deterministic explanations for detected findings.
    explained_findings = explain_repeated_failed_login(
        repeated_failed_login_ips
    )

    # Prepare a minimized set of findings for optional AI analysis.
    # IP addresses and other identifying or raw log data are excluded.
    if ai_analyzer is not None:
        analyze_method = getattr(
            ai_analyzer,
            "analyze_findings",
            None,
        )

        if not callable(analyze_method):
            raise TypeError(
                "AI analyzer must provide a callable "
                "analyze_findings() method."
            )

        ai_findings = [
            {
                "event_type": "repeated_failed_login",
                "severity": finding.get("severity", "unknown"),
                "failed_login_count": finding.get(
                    "failed_login_count"
                ),
            }
            for finding in repeated_failed_login_ips
        ]

        ai_analysis = analyze_method(ai_findings)

    else:
        # Keep the report structure predictable when AI is disabled.
        ai_analysis = {
            "status": "disabled",
            "is_ai_generated": False,
            "ai_analysis": None,
            "findings": [],
            "error": None,
            "sanitized_finding_count": 0,
        }

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

    # Generate offline, rule-based threat context.
    threat_context = generate_threat_context(
        suspicious_events,
        explained_findings,
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

        # Original evidence and investigation data.
        "suspicious_events": suspicious_events,
        "investigation_timeline": investigation_timeline,
        "filtered_events": filtered_events,

        # Detected findings and deterministic explanations.
        "repeated_failed_login_ips": repeated_failed_login_ips,
        "explained_findings": explained_findings,
        "filtered_findings": filtered_findings,

        # Optional AI explanation, kept separate from original evidence.
        "ai_analysis": ai_analysis,

        # Additional offline threat interpretation.
        "threat_context": threat_context,
    }


def export_log_report(
    report: dict,
    output_path: str = "security_log_report.json",
) -> str:
    """Export a security log report to a JSON file."""

    report_file = Path(output_path)
    report_destination = report_file.resolve()

    source_path = report.get("file_path")

    # Prevent accidentally overwriting the original security log.
    if source_path is not None:
        report_source = Path(source_path).resolve()

        if report_source == report_destination:
            raise ValueError(
                "The report output path must not overwrite "
                "the source log file."
            )

    # Export the structured report as formatted JSON.
    report_file.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )

    return str(report_file.resolve())
