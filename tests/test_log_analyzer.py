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


def test_detect_repeated_failed_logins(tmp_path):
    from threatlens_ai.log_analyzer import analyze_log_file

    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "\n".join(
            [
                "Failed password for admin from 192.168.1.50",
                "Failed password for root from 192.168.1.50",
                "Failed password for user from 192.168.1.50",
                "Failed password for admin from 192.168.1.50",
                "Failed password for root from 192.168.1.50",
            ]
        ),
        encoding="utf-8",
    )

    result = analyze_log_file(str(log_file))

    assert len(result["repeated_failed_login_ips"]) == 1
    finding = result["repeated_failed_login_ips"][0]
    assert finding["ip_address"] == "192.168.1.50"
    assert finding["failed_login_count"] == 5
    assert finding["severity"] == "medium"


def test_no_alert_below_threshold(tmp_path):
    from threatlens_ai.log_analyzer import analyze_log_file

    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Failed password for admin from 192.168.1.50\n"
        "Failed password for root from 192.168.1.50\n",
        encoding="utf-8",
    )

    result = analyze_log_file(str(log_file))

    assert result["repeated_failed_login_ips"] == []


def test_high_severity_for_ten_or_more_failures(tmp_path):
    from threatlens_ai.log_analyzer import analyze_log_file

    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "\n".join(
            [
                f"Failed password for admin from 192.168.1.80"
                for _ in range(10)
            ]
        ),
        encoding="utf-8",
    )

    result = analyze_log_file(str(log_file))

    finding = result["repeated_failed_login_ips"][0]
    assert finding["failed_login_count"] == 10
    assert finding["severity"] == "high"


def test_custom_failed_login_threshold(tmp_path):
    from threatlens_ai.log_analyzer import analyze_log_file

    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "\n".join(
            [
                "Failed password for admin from 192.168.1.50",
                "Failed password for root from 192.168.1.50",
                "Failed password for user from 192.168.1.50",
            ]
        ),
        encoding="utf-8",
    )

    result = analyze_log_file(
        str(log_file),
        failed_login_threshold=3,
    )

    assert len(result["repeated_failed_login_ips"]) == 1
    assert result["repeated_failed_login_ips"][0]["failed_login_count"] == 3


def test_invalid_failed_login_threshold(tmp_path):
    from threatlens_ai.log_analyzer import analyze_log_file
    import pytest

    log_file = tmp_path / "auth.log"
    log_file.write_text("", encoding="utf-8")

    for invalid_threshold in (0, -1, 2.5, True):
        with pytest.raises(ValueError, match="positive integer"):
            analyze_log_file(
                str(log_file),
                failed_login_threshold=invalid_threshold,
            )


def test_exactly_five_failed_logins_triggers_medium_alert(tmp_path):
    """Exactly five failures should trigger a medium alert."""
    from threatlens_ai.log_analyzer import analyze_log_file

    log_file = tmp_path / "five_failures.log"
    log_file.write_text(
        "".join(
            f"Failed password for admin from 192.168.1.50 port {5000 + i} ssh2\n"
            for i in range(5)
        ),
        encoding="utf-8",
    )

    result = analyze_log_file(str(log_file))

    assert result["source_ip_counts"]["192.168.1.50"] == 5
    assert result["repeated_failed_login_ips"] == [
        {
            "ip_address": "192.168.1.50",
            "failed_login_count": 5,
            "severity": "medium",
        }
    ]


def test_exactly_ten_failed_logins_triggers_high_alert(tmp_path):
    """Exactly ten failures should trigger a high alert."""
    from threatlens_ai.log_analyzer import analyze_log_file

    log_file = tmp_path / "ten_failures.log"
    log_file.write_text(
        "".join(
            f"Failed password for admin from 192.168.1.50 port {5000 + i} ssh2\n"
            for i in range(10)
        ),
        encoding="utf-8",
    )

    result = analyze_log_file(str(log_file))

    assert result["source_ip_counts"]["192.168.1.50"] == 10
    assert result["repeated_failed_login_ips"] == [
        {
            "ip_address": "192.168.1.50",
            "failed_login_count": 10,
            "severity": "high",
        }
    ]


def test_failed_login_without_ip_is_still_detected(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Failed password for admin\n",
        encoding="utf-8",
    )

    result = analyze_log_file(str(log_file))

    assert result["failed_login_count"] == 1
    assert result["source_ip_counts"] == {}
    assert len(result["suspicious_events"]) == 1
    assert result["suspicious_events"][0]["event_type"] == "failed_login"
