
"""Tests for the ThreatLens AI command-line interface."""

from threatlens_ai import main as main_module


def test_cli_displays_local_ai_option_and_exits(monkeypatch, capsys):
    """Verify that option 12 appears and option 4 exits the CLI."""

    # Simulate the user selecting option 4.
    inputs = iter(["4"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))

    main_module.main()

    output = capsys.readouterr().out

    assert "12. Analyze a security log with Local AI" in output
    assert "Thank you for using ThreatLens AI." in output


def test_cli_local_ai_success(monkeypatch, capsys):
    """Verify that the CLI displays a successful local AI explanation."""

    # Supply a synthetic report without reading a real security log.
    mock_report = {
        "summary": {
            "failed_login_count": 8,
            "repeated_failed_login_ip_count": 1,
        },
        "ai_analysis": {
            "status": "success",
            "ai_analysis": "Repeated login failures deserve investigation.",
            "error": None,
        },
    }

    # Fake provider and analyzer prevent a real AI server connection.
    class MockProvider:
        pass

    class MockAIAnalyzer:
        def __init__(self, provider):
            self.provider = provider

    monkeypatch.setattr(
        main_module,
        "create_ai_provider",
        lambda **kwargs: MockProvider(),
    )
    monkeypatch.setattr(
        main_module,
        "AIAnalyzer",
        MockAIAnalyzer,
    )
    monkeypatch.setattr(
        main_module,
        "generate_log_report",
        lambda *args, **kwargs: mock_report,
    )

    # Simulate selecting option 12 and then exiting.
    inputs = iter(["12", "synthetic_security.log", "5", "4"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))

    main_module.main()

    output = capsys.readouterr().out

    assert "Deterministic Security Analysis" in output
    assert "Failed login events: 8" in output
    assert "Local AI Analysis" in output
    assert "Status: success" in output
    assert "Repeated login failures deserve investigation." in output


def test_cli_local_ai_unavailable_preserves_report(monkeypatch, capsys):
    """Verify that AI failure does not remove deterministic results."""

    # Simulate an unavailable AI service while retaining rule-based results.
    mock_report = {
        "summary": {
            "failed_login_count": 8,
            "repeated_failed_login_ip_count": 1,
        },
        "ai_analysis": {
            "status": "unavailable",
            "ai_analysis": None,
            "error": "Local AI server is unavailable.",
        },
    }

    class MockProvider:
        pass

    class MockAIAnalyzer:
        def __init__(self, provider):
            self.provider = provider

    monkeypatch.setattr(
        main_module,
        "create_ai_provider",
        lambda **kwargs: MockProvider(),
    )
    monkeypatch.setattr(
        main_module,
        "AIAnalyzer",
        MockAIAnalyzer,
    )
    monkeypatch.setattr(
        main_module,
        "generate_log_report",
        lambda *args, **kwargs: mock_report,
    )

    # Simulate selecting option 12 and then exiting.
    inputs = iter(["12", "synthetic_security.log", "5", "4"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))

    main_module.main()

    output = capsys.readouterr().out

    assert "Failed login events: 8" in output
    assert "Repeated failed-login IPs: 1" in output
    assert "Status: unavailable" in output
    assert "Local AI server is unavailable." in output
