
import pytest

from threatlens_ai.threat_context import (
    analyze_ip_context,
    analyze_event_context,
    generate_threat_context,
)


def test_public_ip_is_not_declared_malicious():
    result = analyze_ip_context({
        "valid": True,
        "classification": "public",
    })

    assert result["classification"] == "public"
    assert "does not indicate malicious" in result["context"]
    assert result["investigation_required"] is False


def test_private_ip_is_not_assumed_safe():
    result = analyze_ip_context({
        "valid": True,
        "classification": "private",
    })

    assert result["classification"] == "private"
    assert "suspicious activity" in result["context"]


def test_documentation_ip_is_identified():
    result = analyze_ip_context({
        "valid": True,
        "classification": "documentation",
    })

    assert result["classification"] == "documentation"
    assert "documentation range" in result["context"]


def test_missing_ip_intelligence():
    result = analyze_ip_context(None)

    assert result["classification"] == "unavailable"
    assert result["investigation_required"] is False


def test_invalid_ip_intelligence():
    result = analyze_ip_context({
        "valid": False,
        "classification": "invalid",
    })

    assert result["classification"] == "invalid"
    assert result["investigation_required"] is True


def test_invalid_ip_intelligence_type():
    with pytest.raises(TypeError):
        analyze_ip_context("invalid")


def test_failed_login_event_context():
    result = analyze_event_context({
        "event_type": "failed_login",
        "ip_intelligence": {
            "valid": True,
            "classification": "public",
        },
    })

    assert result["event_type"] == "failed_login"
    assert "does not establish malicious" in result["explanation"]
    assert result["ip_context"]["classification"] == "public"
    assert result["is_ai_generated"] is False


def test_successful_login_is_not_assumed_unauthorized():
    result = analyze_event_context({
        "event_type": "successful_login",
    })

    assert "does not indicate unauthorized access" in result["explanation"]


def test_unknown_event_type():
    result = analyze_event_context({
        "event_type": "unknown_event",
    })

    assert "no specific threat-context rule" in result["explanation"]


def test_invalid_event_type():
    with pytest.raises(ValueError):
        analyze_event_context({
            "event_type": 123,
        })


def test_generate_threat_context():
    events = [
        {
            "event_type": "failed_login",
            "ip_intelligence": {
                "valid": True,
                "classification": "documentation",
            },
        },
        {
            "event_type": "successful_login",
        },
    ]

    findings = [
        {
            "event_type": "repeated_failed_login",
            "severity": "medium",
        },
    ]

    result = generate_threat_context(events, findings)

    assert result["analysis_type"] == "offline_threat_context"
    assert result["event_count"] == 2
    assert result["finding_count"] == 1
    assert len(result["event_contexts"]) == 2
    assert len(result["finding_contexts"]) == 1
    assert result["is_ai_generated"] is False


def test_empty_threat_context():
    result = generate_threat_context([])

    assert result["event_count"] == 0
    assert result["finding_count"] == 0
    assert result["event_contexts"] == []
    assert result["finding_contexts"] == []


def test_invalid_events_argument():
    with pytest.raises(TypeError):
        generate_threat_context("not a list")


def test_invalid_findings_argument():
    with pytest.raises(TypeError):
        generate_threat_context([], "not a list")


def test_invalid_finding_item():
    with pytest.raises(TypeError):
        generate_threat_context([], ["invalid"])


def test_finding_severity_must_be_string():
    with pytest.raises(ValueError):
        generate_threat_context(
            [],
            [{
                "event_type": "repeated_failed_login",
                "severity": 123,
            }],
        )
