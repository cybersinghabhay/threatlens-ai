import json

import pytest

from threatlens_ai.log_report import (
    export_log_report,
    generate_log_report,
)


def test_generate_log_report(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Failed password for admin from 192.168.1.50\n"
        "WARNING: unusual activity\n"
        "ERROR: service unavailable\n",
        encoding="utf-8",
    )

    report = generate_log_report(str(log_file))

    assert report["report_type"] == "security_log_analysis"
    assert report["summary"]["total_lines"] == 3
    assert report["summary"]["failed_login_count"] == 1
    assert report["summary"]["warning_count"] == 1
    assert report["summary"]["error_count"] == 1
    assert report["summary"]["unique_source_ips"] == 1


def test_report_contains_utc_timestamp(tmp_path):
    log_file = tmp_path / "empty.log"
    log_file.write_text("", encoding="utf-8")

    report = generate_log_report(str(log_file))

    assert report["generated_at_utc"].endswith("+00:00")


def test_export_log_report_to_json(tmp_path):
    report = {
        "report_type": "security_log_analysis",
        "summary": {"failed_login_count": 2},
    }
    output_file = tmp_path / "security_log_report.json"

    exported_path = export_log_report(
        report,
        str(output_file),
    )

    assert output_file.exists()
    assert str(output_file.resolve()) == exported_path

    saved_report = json.loads(
        output_file.read_text(encoding="utf-8")
    )
    assert saved_report == report


def test_export_log_report_does_not_overwrite_source_log(tmp_path):
    source = tmp_path / "auth.log"
    original_content = (
        "Failed password for admin from 192.168.1.50\n"
    )
    source.write_text(original_content, encoding="utf-8")

    report = {
        "report_type": "security_log_analysis",
        "file_path": str(source.resolve()),
        "summary": {"failed_login_count": 1},
    }

    with pytest.raises(ValueError, match="must not overwrite"):
        export_log_report(report, str(source))

    assert source.read_text(encoding="utf-8") == original_content


def test_log_report_contains_chronological_investigation_timeline(
    tmp_path,
):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "2026-10-20 10:00:00 WARNING: unusual activity\n"
        "2026-10-20 09:00:00 Failed password for admin from 192.0.2.10\n"
        "2026-10-20 11:00:00 ERROR: service unavailable\n",
        encoding="utf-8",
    )

    report = generate_log_report(str(log_file))

    timeline = report["investigation_timeline"]

    assert len(timeline) == 3
    assert [
        event["event_type"] for event in timeline
    ] == [
        "failed_login",
        "warning",
        "error",
    ]

    assert [
        event["timestamp"] for event in timeline
    ] == [
        "2026-10-20T09:00:00",
        "2026-10-20T10:00:00",
        "2026-10-20T11:00:00",
    ]


def test_log_report_preserves_original_suspicious_event_order(
    tmp_path,
):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "2026-10-20 11:00:00 WARNING: unusual activity\n"
        "2026-10-20 09:00:00 ERROR: service unavailable\n",
        encoding="utf-8",
    )

    report = generate_log_report(str(log_file))

    original_events = report["suspicious_events"]
    timeline = report["investigation_timeline"]

    assert original_events[0]["event_type"] == "warning"
    assert original_events[1]["event_type"] == "error"

    assert timeline[0]["event_type"] == "error"
    assert timeline[1]["event_type"] == "warning"


def test_log_report_places_missing_timestamps_at_the_end(
    tmp_path,
):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "WARNING: event without timestamp\n"
        "2026-10-20 09:00:00 ERROR: timestamped event\n",
        encoding="utf-8",
    )

    report = generate_log_report(str(log_file))

    timeline = report["investigation_timeline"]

    assert timeline[0]["event_type"] == "error"
    assert timeline[1]["event_type"] == "warning"
    assert timeline[1]["timestamp"] is None


def test_exported_json_contains_investigation_timeline(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "2026-10-20 11:00:00 WARNING: unusual activity\n"
        "2026-10-20 09:00:00 ERROR: service unavailable\n",
        encoding="utf-8",
    )

    report = generate_log_report(str(log_file))

    output_file = tmp_path / "security_report.json"

    export_log_report(report, str(output_file))

    saved_report = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert "investigation_timeline" in saved_report
    assert len(saved_report["investigation_timeline"]) == 2

    assert (
        saved_report["investigation_timeline"][0]["event_type"]
        == "error"
    )


def test_log_report_contains_all_events_when_severity_is_all(tmp_path):
    from threatlens_ai.log_report import generate_log_report

    log_file = tmp_path / "mixed.log"
    log_file.write_text(
        "\n".join([
            "Failed password for admin",
            "WARNING: Disk space is low",
            "ERROR: Connection failed",
            "CRITICAL: Service unavailable",
        ]),
        encoding="utf-8",
    )

    report = generate_log_report(log_file)

    assert report["severity_filter"] == "all"
    assert len(report["suspicious_events"]) == 4
    assert len(report["filtered_events"]) == 4


def test_log_report_filters_events_by_severity(tmp_path):
    from threatlens_ai.log_report import generate_log_report

    log_file = tmp_path / "mixed.log"
    log_file.write_text(
        "\n".join([
            "Failed password for admin",
            "WARNING: Disk space is low",
            "ERROR: Connection failed",
            "CRITICAL: Service unavailable",
        ]),
        encoding="utf-8",
    )

    report = generate_log_report(
        log_file,
        severity="critical",
    )

    assert report["severity_filter"] == "critical"
    assert len(report["filtered_events"]) == 1
    assert report["filtered_events"][0]["event_type"] == "critical"


def test_log_report_preserves_original_events_after_filtering(tmp_path):
    from threatlens_ai.log_report import generate_log_report

    log_file = tmp_path / "mixed.log"
    log_file.write_text(
        "WARNING: Disk space is low\n"
        "CRITICAL: Service unavailable\n",
        encoding="utf-8",
    )

    report = generate_log_report(
        log_file,
        severity="critical",
    )

    assert len(report["suspicious_events"]) == 2
    assert len(report["investigation_timeline"]) == 2
    assert len(report["filtered_events"]) == 1


def test_log_report_rejects_invalid_severity(tmp_path):
    from threatlens_ai.log_report import generate_log_report

    log_file = tmp_path / "sample.log"
    log_file.write_text("WARNING: Test warning", encoding="utf-8")

    with pytest.raises(ValueError):
        generate_log_report(log_file, severity="extreme")


def test_log_report_contains_filtered_event_count(tmp_path):
    from threatlens_ai.log_report import generate_log_report

    log_file = tmp_path / "mixed.log"
    log_file.write_text(
        "WARNING: Test warning\n"
        "CRITICAL: Test critical event\n",
        encoding="utf-8",
    )

    report = generate_log_report(
        log_file,
        severity="critical",
    )

    assert report["summary"]["suspicious_event_count"] == 2
    assert report["summary"]["filtered_event_count"] == 1


def test_log_report_contains_threat_context(tmp_path):
    """Verify that the report includes offline threat context."""

    log_file = tmp_path / "security.log"

    log_file.write_text(
        "2026-10-30 10:00:00 Failed password for admin "
        "from 192.0.2.10 port 22 ssh2\n",
        encoding="utf-8",
    )

    report = generate_log_report(
        str(log_file),
        failed_login_threshold=1,
    )

    assert "threat_context" in report
    assert isinstance(report["threat_context"], dict)
    assert report["threat_context"]["is_ai_generated"] is False


def test_exported_json_contains_threat_context(tmp_path):
    """Verify that exported JSON retains threat context."""

    log_file = tmp_path / "security.log"
    output_file = tmp_path / "security_report.json"

    log_file.write_text(
        "2026-10-30 10:00:00 Failed password for admin "
        "from 192.0.2.10 port 22 ssh2\n",
        encoding="utf-8",
    )

    report = generate_log_report(
        str(log_file),
        failed_login_threshold=1,
    )

    export_log_report(report, str(output_file))

    exported_report = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert "threat_context" in exported_report
    assert exported_report["threat_context"]["is_ai_generated"] is False
