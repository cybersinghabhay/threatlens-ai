
import json
from urllib.error import HTTPError, URLError

import pytest

import threatlens_ai.ai.local_provider as local_provider
from threatlens_ai.ai.local_provider import LocalAIProvider, NoRedirectHandler


class MockResponse:
    """Simulate an HTTP response from a local AI server."""

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self, size=-1):
        return self.body[:size]


class MockOpener:
    """Simulate an HTTP opener without making network requests."""

    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.request = None
        self.timeout = None

    def open(self, request, timeout=None):
        self.request = request
        self.timeout = timeout

        if self.error:
            raise self.error

        return self.response


def mock_successful_opener(monkeypatch, response_body):
    """Replace the real network opener with a safe test double."""

    mock_opener = MockOpener(
        response=MockResponse(response_body)
    )

    def mock_build_opener(*handlers):
        return mock_opener

    monkeypatch.setattr(
        local_provider,
        "build_opener",
        mock_build_opener,
    )

    return mock_opener


def test_default_configuration():
    provider = LocalAIProvider()

    assert provider.endpoint == (
        "http://127.0.0.1:8080/v1/chat/completions"
    )
    assert provider.model == "local-model"
    assert provider.timeout == 30


def test_accepts_loopback_endpoint():
    provider = LocalAIProvider(
        endpoint="http://127.0.0.1:8080/v1/chat/completions"
    )

    provider._validate_endpoint()


def test_accepts_ipv6_loopback_endpoint():
    provider = LocalAIProvider(
        endpoint="http://[::1]:8080/v1/chat/completions"
    )

    provider._validate_endpoint()


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:8080/v1/chat/completions",
        "http://example.com:8080/v1/chat/completions",
        "http://localhost:8080/v1/chat/completions",
        "http://192.0.2.10:8080/v1/chat/completions",
        "http://127.0.0.1/v1/chat/completions",
        "http://127.0.0.1:8080/invalid",
        "http://user:password@127.0.0.1:8080/v1/chat/completions",
        "http://127.0.0.1:8080/v1/chat/completions?token=test",
        "http://127.0.0.1:8080/v1/chat/completions#fragment",
    ],
)
def test_rejects_unsafe_endpoints(endpoint):
    provider = LocalAIProvider(endpoint=endpoint)

    with pytest.raises(ValueError):
        provider._validate_endpoint()


@pytest.mark.parametrize(
    "model",
    [
        "",
        "   ",
        None,
        123,
    ],
)
def test_rejects_invalid_model_names(model):
    with pytest.raises(ValueError):
        LocalAIProvider(model=model)


@pytest.mark.parametrize(
    "timeout",
    [
        0,
        -1,
        True,
        float("inf"),
        float("-inf"),
        float("nan"),
        "30",
    ],
)
def test_rejects_invalid_timeouts(timeout):
    with pytest.raises(ValueError):
        LocalAIProvider(timeout=timeout)


def test_analyze_returns_ai_response(monkeypatch):
    response_data = {
        "choices": [
            {
                "message": {
                    "content": "This is a simulated AI response."
                }
            }
        ]
    }

    response_body = json.dumps(response_data).encode("utf-8")

    mock_opener = mock_successful_opener(
        monkeypatch,
        response_body,
    )

    provider = LocalAIProvider()

    result = provider.analyze("Analyze this synthetic security event.")

    assert result == "This is a simulated AI response."

    assert mock_opener.request.get_method() == "POST"
    assert mock_opener.timeout == 30

    payload = json.loads(mock_opener.request.data.decode("utf-8"))

    assert payload["model"] == "local-model"
    assert payload["messages"][0]["content"] == (
        "Analyze this synthetic security event."
    )


@pytest.mark.parametrize(
    "prompt",
    [
        "",
        "   ",
        None,
        123,
    ],
)
def test_rejects_invalid_prompts(prompt):
    provider = LocalAIProvider()

    with pytest.raises(ValueError):
        provider.analyze(prompt)


def test_http_error_is_handled_safely(monkeypatch):
    mock_opener = MockOpener(
        error=HTTPError(
            "http://127.0.0.1:8080/v1/chat/completions",
            500,
            "Server Error",
            {},
            None,
        )
    )

    monkeypatch.setattr(
        local_provider,
        "build_opener",
        lambda *handlers: mock_opener,
    )

    provider = LocalAIProvider()

    with pytest.raises(RuntimeError, match="HTTP error"):
        provider.analyze("Synthetic test prompt.")


def test_connection_error_is_handled_safely(monkeypatch):
    mock_opener = MockOpener(
        error=URLError("Connection refused")
    )

    monkeypatch.setattr(
        local_provider,
        "build_opener",
        lambda *handlers: mock_opener,
    )

    provider = LocalAIProvider()

    with pytest.raises(RuntimeError, match="Could not communicate"):
        provider.analyze("Synthetic test prompt.")


def test_prompt_is_not_exposed_in_connection_error(monkeypatch):
    mock_opener = MockOpener(
        error=URLError("Connection refused")
    )

    monkeypatch.setattr(
        local_provider,
        "build_opener",
        lambda *handlers: mock_opener,
    )

    provider = LocalAIProvider()
    sensitive_prompt = "SYNTHETIC_SECRET_TEST_VALUE"

    with pytest.raises(RuntimeError) as error:
        provider.analyze(sensitive_prompt)

    assert sensitive_prompt not in str(error.value)


def test_invalid_json_response_is_handled(monkeypatch):
    mock_successful_opener(
        monkeypatch,
        b"not valid json",
    )

    provider = LocalAIProvider()

    with pytest.raises(RuntimeError, match="invalid JSON"):
        provider.analyze("Synthetic test prompt.")


def test_unexpected_response_structure_is_handled(monkeypatch):
    response_body = json.dumps(
        {"unexpected": "structure"}
    ).encode("utf-8")

    mock_successful_opener(
        monkeypatch,
        response_body,
    )

    provider = LocalAIProvider()

    with pytest.raises(RuntimeError, match="unexpected response"):
        provider.analyze("Synthetic test prompt.")


def test_empty_ai_response_is_rejected(monkeypatch):
    response_data = {
        "choices": [
            {
                "message": {
                    "content": "   "
                }
            }
        ]
    }

    mock_successful_opener(
        monkeypatch,
        json.dumps(response_data).encode("utf-8"),
    )

    provider = LocalAIProvider()

    with pytest.raises(RuntimeError, match="empty or invalid"):
        provider.analyze("Synthetic test prompt.")


def test_oversized_response_is_rejected(monkeypatch):
    provider = LocalAIProvider()

    oversized_body = b"x" * (provider.MAX_RESPONSE_SIZE + 1)

    mock_successful_opener(
        monkeypatch,
        oversized_body,
    )

    with pytest.raises(RuntimeError, match="size limit"):
        provider.analyze("Synthetic test prompt.")


def test_redirect_handler_blocks_redirects():
    handler = NoRedirectHandler()

    result = handler.redirect_request(
        None,
        None,
        302,
        "Found",
        {},
        "http://example.com/",
    )

    assert result is None


def test_redirect_handler_is_passed_to_opener(monkeypatch):
    captured_handlers = []

    def mock_build_opener(*handlers):
        captured_handlers.extend(handlers)
        return MockOpener(
            response=MockResponse(
                json.dumps(
                    {
                        "choices": [
                            {
                                "message": {
                                    "content": "Safe response."
                                }
                            }
                        ]
                    }
                ).encode("utf-8")
            )
        )

    monkeypatch.setattr(
        local_provider,
        "build_opener",
        mock_build_opener,
    )

    provider = LocalAIProvider()

    assert provider.analyze("Synthetic test prompt.") == "Safe response."

    assert any(
        isinstance(handler, NoRedirectHandler)
        for handler in captured_handlers
    )
