
import pytest

from threatlens_ai.severity_filter import (
    filter_by_severity,
    filter_events_by_severity,
    filter_findings_by_severity,
    validate_severity_filter,
)


def test_validate_all_severities():
    assert validate_severity_filter("all") == "all"
    assert validate_severity_filter("HIGH") == "high"
    assert validate_severity_filter(" Medium ") == "medium"


def test_invalid_severity_is_rejected():
    with pytest.raises(ValueError, match="Invalid severity"):
        validate_severity_filter("extreme")


def test_non_string_severity_is_rejected():
    with pytest.raises(ValueError, match="must be a string"):
        validate_severity_filter(None)


def test_filter_events_by_severity():
    events = [
        {"event_type": "critical", "severity": "critical"},
        {"event_type": "warning", "severity": "low"},
        {"event_type": "error", "severity": "medium"},
    ]

    result = filter_events_by_severity(events, "critical")

    assert result == [
        {"event_type": "critical", "severity": "critical"}
    ]


def test_filter_findings_by_severity():
    findings = [
        {"event_type": "login", "severity": "high"},
        {"event_type": "file", "severity": "medium"},
    ]

    result = filter_findings_by_severity(findings, "high")

    assert len(result) == 1
    assert result[0]["severity"] == "high"


def test_all_filter_returns_every_item():
    items = [{"severity": "high"}, {"severity": "low"}]

    assert filter_by_severity(items, "all") == items


def test_filter_does_not_modify_original_list():
    items = [
        {"severity": "high"},
        {"severity": "low"},
    ]

    original = items.copy()

    filter_by_severity(items, "high")

    assert items == original


def test_unknown_severity_can_be_filtered():
    items = [
        {"severity": "unknown"},
        {"severity": "high"},
    ]

    assert filter_by_severity(items, "unknown") == [
        {"severity": "unknown"}
    ]


def test_non_list_input_is_rejected():
    with pytest.raises(TypeError, match="must be a list"):
        filter_by_severity("not a list", "high")


def test_items_without_severity_are_not_in_specific_filter():
    items = [
        {"event_type": "warning"},
        {"event_type": "error", "severity": "medium"},
    ]

    assert filter_by_severity(items, "medium") == [
        {"event_type": "error", "severity": "medium"}
    ]
