import pytest

from threatlens_ai.finding_integration import (
    explain_repeated_failed_login,
)


def test_explain_repeated_failed_login():
    findings = [
        {
            "ip_address": "192.0.2.10",
            "failed_login_count": 12,
            "severity": "high",
        }
    ]

    result = explain_repeated_failed_login(findings)

    assert len(result) == 1
    assert result[0]["event_type"] == "repeated_failed_login"
    assert result[0]["severity"] == "high"
    assert result[0]["ip_address"] == "192.0.2.10"
    assert result[0]["failed_login_count"] == 12
    assert "brute-force" in result[0]["explanation"]
    assert result[0]["is_ai_generated"] is False


def test_explain_multiple_findings():
    findings = [
        {"ip_address": "192.0.2.10", "severity": "high"},
        {"ip_address": "198.51.100.20", "severity": "medium"},
    ]

    result = explain_repeated_failed_login(findings)

    assert len(result) == 2
    assert result[0]["severity"] == "high"
    assert result[1]["severity"] == "medium"


def test_explain_finding_with_missing_severity():
    findings = [{"ip_address": "192.0.2.10"}]

    result = explain_repeated_failed_login(findings)

    assert result[0]["severity"] == "unknown"


def test_reject_non_list_findings():
    with pytest.raises(TypeError, match="findings must be a list"):
        explain_repeated_failed_login("invalid")


def test_reject_non_dictionary_finding():
    with pytest.raises(TypeError, match="Each finding must be a dictionary"):
        explain_repeated_failed_login(["invalid"])


def test_empty_findings_list():
    result = explain_repeated_failed_login([])

    assert result == []