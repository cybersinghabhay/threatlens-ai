
import pytest

from threatlens_ai.log_report import generate_log_report
from threatlens_ai.ai.analyzer import AIAnalyzer


class MockAIProvider:
    """Mock provider for testing without a real AI server."""

    def __init__(self, response="Mock AI explanation", error=None):
        self.response = response
        self.error = error
        self.prompt = None
        self.call_count = 0

    def analyze(self, prompt):
        self.call_count += 1
        self.prompt = prompt

        if self.error is not None:
            raise self.error

        return self.response


class MockAIAnalyzer:
    """Mock AI analyzer for testing report integration."""

    def __init__(self, result=None):
        self.result = result
        self.received_findings = None
        self.call_count = 0

    def analyze_findings(self, findings):
        self.call_count += 1
        self.received_findings = findings

        return self.result


def create_repeated_login_log(tmp_path):
    """Create a synthetic log with repeated failed logins."""

    log_file = tmp_path / "synthetic_auth.log"

    log_file.write_text(
        "Failed password for admin from 192.0.2.10\n"
        "Failed password for admin from 192.0.2.10\n"
        "Failed password for admin from 192.0.2.10\n"
        "Failed password for admin from 192.0.2.10\n"
        "Failed password for admin from 192.0.2.10\n",
        encoding="utf-8",
    )

    return log_file


def test_ai_analyzer_receives_repeated_login_findings(tmp_path):
    """Verify repeated-login findings reach the AI analyzer."""

    log_file = create_repeated_login_log(tmp_path)

    ai_result = {
        "status": "success",
        "is_ai_generated": True,
        "ai_analysis": "Repeated failed logins were detected.",
        "findings": [],
        "error": None,
        "sanitized_finding_count": 1,
    }

    mock_analyzer = MockAIAnalyzer(result=ai_result)

    report = generate_log_report(
        str(log_file),
        failed_login_threshold=5,
        ai_analyzer=mock_analyzer,
    )

    assert mock_analyzer.call_count == 1
    assert len(mock_analyzer.received_findings) == 1
    assert mock_analyzer.received_findings[0]["severity"] == "medium"

    assert report["ai_analysis"]["status"] == "success"
    assert (
        report["ai_analysis"]["ai_analysis"]
        == "Repeated failed logins were detected."
    )


def test_ai_analyzer_does_not_receive_ip_addresses(tmp_path):
    """Verify IP addresses are excluded before AI analysis."""

    log_file = create_repeated_login_log(tmp_path)

    mock_analyzer = MockAIAnalyzer(
        result={
            "status": "success",
            "is_ai_generated": True,
            "ai_analysis": "Safe explanation.",
            "findings": [],
            "error": None,
            "sanitized_finding_count": 1,
        }
    )

    report = generate_log_report(
        str(log_file),
        failed_login_threshold=5,
        ai_analyzer=mock_analyzer,
    )

    received = mock_analyzer.received_findings

    assert received is not None
    assert "ip_address" not in received[0]
    assert "192.0.2.10" not in str(received)


def test_ai_analyzer_does_not_receive_raw_log_messages_or_paths(
    tmp_path,
):
    """Verify raw log messages and paths are excluded."""

    log_file = create_repeated_login_log(tmp_path)

    mock_analyzer = MockAIAnalyzer(
        result={
            "status": "success",
            "is_ai_generated": True,
            "ai_analysis": "Safe explanation.",
            "findings": [],
            "error": None,
            "sanitized_finding_count": 1,
        }
    )

    report = generate_log_report(
        str(log_file),
        failed_login_threshold=5,
        ai_analyzer=mock_analyzer,
    )

    received = str(mock_analyzer.received_findings)

    assert "Failed password for admin" not in received
    assert str(log_file.resolve()) not in received


def test_ai_provider_failure_preserves_log_report(tmp_path):
    """Verify AI failure does not interrupt rule-based reporting."""

    log_file = create_repeated_login_log(tmp_path)

    mock_analyzer = MockAIAnalyzer(
        result={
            "status": "unavailable",
            "is_ai_generated": False,
            "ai_analysis": None,
            "findings": [],
            "error": "AI analysis could not be completed.",
            "sanitized_finding_count": 1,
        }
    )

    report = generate_log_report(
        str(log_file),
        failed_login_threshold=5,
        ai_analyzer=mock_analyzer,
    )

    assert report["summary"]["failed_login_count"] == 5
    assert len(report["repeated_failed_login_ips"]) == 1

    assert report["ai_analysis"]["status"] == "unavailable"
    assert report["ai_analysis"]["ai_analysis"] is None


def test_ai_analyzer_is_skipped_when_no_repeated_findings_exist(
    tmp_path,
):
    """Verify the AI analyzer is not called without findings."""

    log_file = tmp_path / "no_findings.log"

    log_file.write_text(
        "Failed password for admin from 192.0.2.10\n"
        "WARNING: unusual activity\n",
        encoding="utf-8",
    )

    mock_analyzer = MockAIAnalyzer(
        result={
            "status": "skipped",
            "is_ai_generated": False,
            "ai_analysis": None,
            "findings": [],
            "error": None,
            "sanitized_finding_count": 0,
        }
    )

    report = generate_log_report(
        str(log_file),
        failed_login_threshold=5,
        ai_analyzer=mock_analyzer,
    )

    assert mock_analyzer.call_count == 1
    assert mock_analyzer.received_findings == []
    assert report["ai_analysis"]["status"] == "skipped"


def test_original_findings_remain_unchanged_after_ai_analysis(
    tmp_path,
):
    """Verify AI integration does not modify original findings."""

    log_file = create_repeated_login_log(tmp_path)

    mock_analyzer = MockAIAnalyzer(
        result={
            "status": "success",
            "is_ai_generated": True,
            "ai_analysis": "Additional explanation.",
            "findings": [],
            "error": None,
            "sanitized_finding_count": 1,
        }
    )

    report = generate_log_report(
        str(log_file),
        failed_login_threshold=5,
        ai_analyzer=mock_analyzer,
    )

    original_finding = report["repeated_failed_login_ips"][0]

    assert original_finding["ip_address"] == "192.0.2.10"
    assert original_finding["failed_login_count"] == 5
    assert original_finding["severity"] == "medium"

    assert "ai_analysis" not in original_finding
def test_real_ai_analyzer_sanitizes_log_findings(tmp_path):
    """Verify the real AIAnalyzer sanitizes findings before provider use."""

    log_file = create_repeated_login_log(tmp_path)

    provider = MockAIProvider()

    ai_analyzer = AIAnalyzer(provider)

    report = generate_log_report(
        str(log_file),
        failed_login_threshold=5,
        ai_analyzer=ai_analyzer,
    )

    assert report["ai_analysis"]["status"] == "success"

    assert "192.0.2.10" not in provider.prompt
    assert "admin" not in provider.prompt
    assert "synthetic_auth.log" not in provider.prompt
    assert "failed_login_count" in provider.prompt