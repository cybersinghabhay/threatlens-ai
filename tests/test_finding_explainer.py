
import pytest

from threatlens_ai.finding_explainer import explain_finding


def test_explain_repeated_failed_login():
    finding = {
        "event_type": "repeated_failed_login",
        "severity": "high",
    }

    result = explain_finding(finding)

    assert result["event_type"] == "repeated_failed_login"
    assert result["severity"] == "high"
    assert "brute-force" in result["explanation"]
    assert "authentication logs" in result["recommended_action"]
    assert result["is_ai_generated"] is False


def test_explain_file_modified():
    finding = {
        "event_type": "file_modified",
        "severity": "medium",
    }

    result = explain_finding(finding)

    assert "integrity baseline" in result["explanation"]
    assert "authorized" in result["recommended_action"]


def test_explain_unknown_event():
    finding = {
        "event_type": "unknown_event",
        "severity": "low",
    }

    result = explain_finding(finding)

    assert "No specific explanation rule" in result["explanation"]
    assert result["event_type"] == "unknown_event"


def test_explain_missing_fields():
    result = explain_finding({})

    assert result["event_type"] == "unknown"
    assert result["severity"] == "unknown"
    assert result["is_ai_generated"] is False


@pytest.mark.parametrize("finding", ["invalid", None, 123, []])
def test_reject_non_dictionary_finding(finding):
    with pytest.raises(TypeError, match="finding must be a dictionary"):
        explain_finding(finding)


def test_reject_non_string_event_type():
    with pytest.raises(ValueError, match="event_type must be a string"):
        explain_finding({"event_type": 123})


def test_reject_non_string_severity():
    with pytest.raises(ValueError, match="severity must be a string"):
        explain_finding({"severity": 123})
