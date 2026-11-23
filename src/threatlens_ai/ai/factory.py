
from threatlens_ai.ai.local_provider import LocalAIProvider


def create_ai_provider(
    provider_type: str = "local",
    endpoint: str = "http://127.0.0.1:8080/v1/chat/completions",
    model: str = "local-model",
    timeout: int = 30,
):
    """
    Create an AI provider based on the requested provider type.

    Currently supported:
        - local: Local OpenAI-compatible AI server.

    Cloud providers are intentionally not enabled yet.
    """

    if not isinstance(provider_type, str):
        raise ValueError(
            "Provider type must be a string."
        )

    selected_provider = provider_type.strip().lower()

    if selected_provider == "local":
        return LocalAIProvider(
            endpoint=endpoint,
            model=model,
            timeout=timeout,
        )

    raise ValueError(
        f"Unsupported AI provider type: {selected_provider or 'empty'}."
    )
