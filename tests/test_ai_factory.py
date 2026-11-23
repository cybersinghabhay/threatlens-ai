
import pytest

from threatlens_ai.ai.factory import create_ai_provider
from threatlens_ai.ai.local_provider import LocalAIProvider


def test_factory_creates_local_provider():
    provider = create_ai_provider(provider_type="local")

    assert isinstance(provider, LocalAIProvider)


def test_factory_uses_default_local_configuration():
    provider = create_ai_provider(provider_type="local")

    assert provider.endpoint == (
        "http://127.0.0.1:8080/v1/chat/completions"
    )
    assert provider.model == "local-model"
    assert provider.timeout == 30


def test_factory_accepts_custom_local_configuration():
    provider = create_ai_provider(
        provider_type="local",
        endpoint="http://127.0.0.1:9000/v1/chat/completions",
        model="test-local-model",
        timeout=45,
    )

    assert isinstance(provider, LocalAIProvider)
    assert provider.endpoint == (
        "http://127.0.0.1:9000/v1/chat/completions"
    )
    assert provider.model == "test-local-model"
    assert provider.timeout == 45


@pytest.mark.parametrize(
    "provider_type",
    [
        "cloud",
        "unknown",
        "",
        None,
        123,
    ],
)
def test_factory_rejects_unsupported_provider_types(provider_type):
    with pytest.raises(ValueError):
        create_ai_provider(provider_type=provider_type)
