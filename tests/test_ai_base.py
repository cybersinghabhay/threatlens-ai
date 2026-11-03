
import pytest

from threatlens_ai.ai.base import BaseAIProvider


def test_base_ai_provider_cannot_be_instantiated():
    with pytest.raises(TypeError):
        BaseAIProvider()


def test_child_provider_must_implement_analyze():
    class IncompleteProvider(BaseAIProvider):
        pass

    with pytest.raises(TypeError):
        IncompleteProvider()


def test_child_provider_can_implement_analyze():
    class MockAIProvider(BaseAIProvider):
        def analyze(self, prompt: str) -> str:
            return f"Analysis of: {prompt}"

    provider = MockAIProvider()

    result = provider.analyze("Repeated failed login attempts")

    assert result == "Analysis of: Repeated failed login attempts"
