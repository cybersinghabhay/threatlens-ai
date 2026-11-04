import pytest

from threatlens_ai.ai.local_provider import LocalAIProvider


def test_accepts_localhost_endpoint():
    provider = LocalAIProvider()

    provider._validate_endpoint()


def test_rejects_remote_endpoint():
    provider = LocalAIProvider(
        endpoint="http://example.com:8080/v1/chat/completions"
    )

    with pytest.raises(ValueError):
        provider._validate_endpoint()


def test_rejects_https_endpoint():
    provider = LocalAIProvider(
        endpoint="https://127.0.0.1:8080/v1/chat/completions"
    )

    with pytest.raises(ValueError):
        provider._validate_endpoint()


def test_rejects_invalid_api_path():
    provider = LocalAIProvider(
        endpoint="http://127.0.0.1:8080/invalid"
    )

    with pytest.raises(ValueError):
        provider._validate_endpoint()


def test_rejects_url_credentials():
    provider = LocalAIProvider(
        endpoint="http://user:password@127.0.0.1:8080/v1/chat/completions"
    )

    with pytest.raises(ValueError):
        provider._validate_endpoint()

def test_rejects_empty_model_name():
    with pytest.raises(ValueError):
        LocalAIProvider(model="")


def test_rejects_empty_model_name_with_spaces():
    with pytest.raises(ValueError):
        LocalAIProvider(model="   ")


@pytest.mark.parametrize("timeout", [0, -1, True, False, float("inf"), float("nan")])
def test_rejects_invalid_timeout(timeout):
    with pytest.raises(ValueError):
        LocalAIProvider(timeout=timeout)


def test_accepts_valid_timeout():
    provider = LocalAIProvider(timeout=30)
    assert provider.timeout == 30