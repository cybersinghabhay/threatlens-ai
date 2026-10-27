import pytest
import html

from threatlens_ai.html_report import export_html_report


def test_export_html_report_creates_file(tmp_path):
    report = {
        "report_type": "security_log_analysis",
        "summary": {
            "failed_login_count": 2,
            "warning_count": 1,
        },
    }
    output_file = tmp_path / "security_report.html"

    saved_path = export_html_report(
        report,
        str(output_file),
    )

    assert output_file.is_file()
    assert saved_path == str(output_file.resolve())


def test_html_report_contains_report_data(tmp_path):
    report = {
        "report_type": "security_log_analysis",
        "summary": {"failed_login_count": 3},
    }
    output_file = tmp_path / "security_report.html"

    export_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert "<!DOCTYPE html>" in content
    assert "ThreatLens AI Security Report" in content
    assert "security_log_analysis" in html.unescape(content)
    assert "failed_login_count" in html.unescape(content)
    assert "3" in html.unescape(content)


def test_html_report_escapes_untrusted_content(tmp_path):
    malicious_value = "<script>alert('test')</script>"
    report = {"event_message": malicious_value}
    output_file = tmp_path / "security_report.html"

    export_html_report(report, str(output_file))

    content = output_file.read_text(encoding="utf-8")

    assert malicious_value not in content
    assert html.escape(malicious_value) in content


def test_html_report_displays_summary_and_security_findings(tmp_path):
    report = {
        "report_type": "security_log_analysis",
        "generated_at_utc": "2026-10-27T10:00:00+00:00",
        "file_path": "auth.log",
        "summary": {
            "total_lines": 20,
            "failed_login_count": 8,
            "warning_count": 2,
            "error_count": 1,
            "unique_source_ips": 1,
            "suspicious_event_count": 1,
        },
        "repeated_failed_login_ips": [
            {"ip": "192.0.2.10", "count": 8, "severity": "medium"}
        ],
        "suspicious_events": [
            {
                "line_number": 7,
                "event_type": "failed_login",
                "message": "Failed password for admin",
            }
        ],
    }
    output_file = tmp_path / "dashboard.html"

    export_html_report(report, str(output_file))
    content = output_file.read_text(encoding="utf-8")

    assert "Analysis Summary" in content
    assert "Total Log Lines" in content
    assert "Failed Logins" in content
    assert "Repeated Failed-Login IPs" in content
    assert "192.0.2.10" in content
    assert "medium" in content
    assert "Suspicious Events" in content
    assert "Failed password for admin" in content


def test_html_report_escapes_malicious_event_fields(tmp_path):
    report = {
        "report_type": "security_log_analysis",
        "summary": {},
        "suspicious_events": [
            {
                "line_number": 1,
                "event_type": "<script>alert(1)</script>",
                "message": "<img src=x onerror=alert(1)>",
            }
        ],
    }
    output_file = tmp_path / "safe_dashboard.html"

    export_html_report(report, str(output_file))
    content = output_file.read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in content
    assert "<img src=x onerror=alert(1)>" not in content
    assert "&lt;script&gt;" in content
    assert "&lt;img" in content


def test_html_report_does_not_overwrite_source_log(tmp_path):
    source_log = tmp_path / "auth.log"
    source_log.write_text(
        "Failed password for admin\n",
        encoding="utf-8",
    )

    report = {
        "report_type": "security_log_analysis",
        "file_path": str(source_log),
        "summary": {},
        "suspicious_events": [],
        "repeated_failed_login_ips": [],
    }

    original_content = source_log.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="must not overwrite"):
        export_html_report(report, str(source_log))

    assert source_log.read_text(encoding="utf-8") == original_content
