import pytest
import json

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