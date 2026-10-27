
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
