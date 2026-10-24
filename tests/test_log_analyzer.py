
import pytest

from threatlens_ai.log_analyzer import analyze_log_file


def test_analyze_empty_log_file(tmp_path):
    log_file = tmp_path / "empty.log"
    log_file.write_text("", encoding="utf-8")

    report = analyze_log_file(str(log_file))

    assert report["total_lines"] == 0
    assert report["failed_login_count"] == 0
    assert report["warning_count"] == 0
    assert report["error_count"] == 0
    assert report["suspicious_events"] == []


def test_detect_failed_login(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Failed password for admin from 192.168.1.50 port 5221 ssh2\n",
        encoding="utf-8",
    )

    report = analyze_log_file(str(log_file))

    assert report["failed_login_count"] == 1
    assert report["source_ip_counts"] == {"192.168.1.50": 1}
    assert report["suspicious_events"][0]["event_type"] == "failed_login"


def test_detect_multiple_failed_logins_from_same_ip(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Failed password for admin from 192.168.1.50 port 5221 ssh2\n"
        "Failed password for root from 192.168.1.50 port 5222 ssh2\n",
        encoding="utf-8",
    )

    report = analyze_log_file(str(log_file))

    assert report["failed_login_count"] == 2
    assert report["source_ip_counts"] == {"192.168.1.50": 2}


def test_detect_warning_and_error_messages(tmp_path):
    log_file = tmp_path / "system.log"
    log_file.write_text(
        "WARNING: unusual activity\n"
        "ERROR: service unavailable\n"
        "CRITICAL: system failure\n",
        encoding="utf-8",
    )

    report = analyze_log_file(str(log_file))

    assert report["warning_count"] == 1
    assert report["error_count"] == 2


def test_missing_log_file_raises_error(tmp_path):
    log_file = tmp_path / "missing.log"

    with pytest.raises(FileNotFoundError):
        analyze_log_file(str(log_file))


def test_directory_path_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="Expected a file"):
        analyze_log_file(str(tmp_path))


def test_failed_login_matching_is_case_insensitive(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "FAILED PASSWORD for admin from 10.0.0.5\n",
        encoding="utf-8",
    )

    report = analyze_log_file(str(log_file))

    assert report["failed_login_count"] == 1
    assert report["source_ip_counts"] == {"10.0.0.5": 1}


def test_report_contains_line_numbers(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Normal system message\n"
        "Failed password for admin from 10.0.0.5\n",
        encoding="utf-8",
    )

    report = analyze_log_file(str(log_file))

    assert report["suspicious_events"][0]["line_number"] == 2
