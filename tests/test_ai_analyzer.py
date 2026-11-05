
import pytest

from threatlens_ai.ai.analyzer import AIAnalyzer


class MockAIProvider:
    """A mock provider for testing AIAnalyzer without a real AI server."""

    def __init__(self, response="This activity may indicate repeated login attempts."):
        self.response = response
        self.received_prompt = None
        self.call_count = 0

    def analyze(self, prompt):
        self.call_count += 1
        self.received_prompt = prompt

        if isinstance(self.response, Exception):
            raise self.response

        return self.response


def test_successful_analysis():
    provider = MockAIProvider()
    analyzer = AIAnalyzer(provider)

    findings = [
        {
            "event_type": "repeated_failed_login",
            "severity": "high",
            "failed_login_count": 12,
        }
    ]

    result = analyzer.analyze_findings(findings)

    assert result["status"] == "success"
    assert result["is_ai_generated"] is True
    assert result["ai_analysis"] == provider.response
    assert result["findings"] == findings
    assert result["error"] is None
    assert result["sanitized_finding_count"] == 1
    assert provider.call_count == 1


def test_ai_prompt_contains_approved_fields():
    provider = MockAIProvider()
    analyzer = AIAnalyzer(provider)

    findings = [
        {
            "event_type": "repeated_failed_login",
            "severity": "high",
            "failed_login_count": 12,
        }
    ]

    analyzer.analyze_findings(findings)

    prompt = provider.received_prompt

    assert "repeated_failed_login" in prompt
    assert "high" in prompt
    assert "failed_login_count" in prompt
    assert "12" in prompt


def test_sensitive_information_is_excluded_from_prompt():
    provider = MockAIProvider()
    analyzer = AIAnalyzer(provider)

    findings = [
        {
            "event_type": "repeated_failed_login",
            "severity": "high",
            "failed_login_count": 12,
            "ip_address": "192.0.2.10",
            "username": "test-user-secret",
            "message": "Sensitive authentication log content",
            "file_path": "C:/private/security.log",
            "password": "example-secret-password",
        }
    ]

    analyzer.analyze_findings(findings)

    prompt = provider.received_prompt

    assert "192.0.2.10" not in prompt
    assert "test-user-secret" not in prompt
    assert "Sensitive authentication log content" not in prompt
    assert "C:/private/security.log" not in prompt
    assert "example-secret-password" not in prompt


def test_original_findings_are_preserved():
    provider = MockAIProvider()
    analyzer = AIAnalyzer(provider)

    findings = [
        {
            "event_type": "repeated_failed_login",
            "severity": "high",
            "failed_login_count": 12,
            "ip_address": "192.0.2.10",
        }
    ]

    original_findings = [dict(finding) for finding in findings]

    analyzer.analyze_findings(findings)

    assert findings == original_findings


def test_empty_findings_skip_provider():
    provider = MockAIProvider()
    analyzer = AIAnalyzer(provider)

    result = analyzer.analyze_findings([])

    assert result["status"] == "skipped"
    assert result["is_ai_generated"] is False
    assert result["ai_analysis"] is None
    assert result["findings"] == []
    assert result["sanitized_finding_count"] == 0
    assert provider.call_count == 0


def test_multiple_findings_are_supported():
    provider = MockAIProvider()
    analyzer = AIAnalyzer(provider)

    findings = [
        {
            "event_type": "repeated_failed_login",
            "severity": "high",
            "failed_login_count": 12,
        },
        {
            "event_type": "file_modified",
            "severity": "medium",
        },
    ]

    result = analyzer.analyze_findings(findings)

    assert result["status"] == "success"
    assert result["sanitized_finding_count"] == 2
    assert len(result["findings"]) == 2


def test_non_list_findings_are_rejected():
    analyzer = AIAnalyzer(MockAIProvider())

    with pytest.raises(TypeError, match="list"):
        analyzer.analyze_findings("invalid")


def test_non_dictionary_finding_is_rejected():
    analyzer = AIAnalyzer(MockAIProvider())

    with pytest.raises(TypeError, match="dictionary"):
        analyzer.analyze_findings(["invalid"])


def test_provider_without_analyze_method_is_rejected():
    with pytest.raises(TypeError, match="analyze"):
        AIAnalyzer(object())


def test_provider_failure_preserves_original_findings():
    provider = MockAIProvider(
        response=RuntimeError("Sensitive internal error")
    )
    analyzer = AIAnalyzer(provider)

    findings = [
        {
            "event_type": "repeated_failed_login",
            "severity": "high",
            "failed_login_count": 12,
        }
    ]

    result = analyzer.analyze_findings(findings)

    assert result["status"] == "unavailable"
    assert result["is_ai_generated"] is False
    assert result["ai_analysis"] is None
    assert result["findings"] == findings
    assert result["error"] is not None
    assert "Sensitive internal error" not in result["error"]


@pytest.mark.parametrize("invalid_response", [
    None,
    "",
    "   ",
    123,
    [],
    {},
])
def test_invalid_provider_responses_are_rejected_safely(invalid_response):
    provider = MockAIProvider(response=invalid_response)
    analyzer = AIAnalyzer(provider)

    findings = [
        {
            "event_type": "repeated_failed_login",
            "severity": "high",
        }
    ]

    result = analyzer.analyze_findings(findings)

    assert result["status"] == "unavailable"
    assert result["ai_analysis"] is None
    assert result["findings"] == findings


def test_missing_fields_use_unknown_defaults():
    provider = MockAIProvider()
    analyzer = AIAnalyzer(provider)

    analyzer.analyze_findings([{}])

    assert '"event_type":"unknown"' in provider.received_prompt
    assert '"severity":"unknown"' in provider.received_prompt


def test_invalid_event_type_is_rejected():
    analyzer = AIAnalyzer(MockAIProvider())

    with pytest.raises(ValueError, match="event_type"):
        analyzer.analyze_findings([
            {
                "event_type": 123,
                "severity": "high",
            }
        ])


def test_invalid_severity_is_rejected():
    analyzer = AIAnalyzer(MockAIProvider())

    with pytest.raises(ValueError, match="severity"):
        analyzer.analyze_findings([
            {
                "event_type": "repeated_failed_login",
                "severity": 123,
            }
        ])


def test_invalid_count_is_excluded_from_prompt():
    provider = MockAIProvider()
    analyzer = AIAnalyzer(provider)

    analyzer.analyze_findings([
        {
            "event_type": "repeated_failed_login",
            "severity": "high",
            "failed_login_count": True,
        }
    ])

    assert "failed_login_count" not in provider.received_prompt


def test_negative_count_is_excluded_from_prompt():
    provider = MockAIProvider()
    analyzer = AIAnalyzer(provider)

    analyzer.analyze_findings([
        {
            "event_type": "repeated_failed_login",
            "severity": "high",
            "failed_login_count": -5,
        }
    ])

    assert "failed_login_count" not in provider.received_prompt


def test_finding_limit_is_enforced():
    analyzer = AIAnalyzer(MockAIProvider())

    findings = [
        {"event_type": "test", "severity": "low"}
        for _ in range(AIAnalyzer.MAX_FINDINGS + 1)
    ]

    with pytest.raises(ValueError, match="maximum"):
        analyzer.analyze_findings(findings)


def test_field_length_is_limited():
    provider = MockAIProvider()
    analyzer = AIAnalyzer(provider)

    long_event_type = "a" * 200

    analyzer.analyze_findings([
        {
            "event_type": long_event_type,
            "severity": "high",
        }
    ])

    assert long_event_type not in provider.received_prompt
    assert "a" * AIAnalyzer.MAX_FIELD_LENGTH in provider.received_prompt

def test_excessively_large_count_is_excluded_from_prompt():
    provider = MockAIProvider()
    analyzer = AIAnalyzer(provider)

    analyzer.analyze_findings([
        {
            "event_type": "repeated_failed_login",
            "severity": "high",
            "failed_login_count": AIAnalyzer.MAX_COUNT + 1,
        }
    ])

    assert "failed_login_count" not in provider.received_prompt