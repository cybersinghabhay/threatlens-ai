
import json
import math

from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from threatlens_ai.ai.base import BaseAIProvider


class LocalAIProvider(BaseAIProvider):
    """
    Connects ThreatLens AI to a locally running,
    OpenAI-compatible AI server.
    """

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:8080/v1/chat/completions",
        model: str = "local-model",
        timeout: int = 30,
    ):
        self.endpoint = endpoint
        self.model = model
        self.timeout = timeout

        if not isinstance(self.model, str) or not self.model.strip():
            raise ValueError("Model name must be a non-empty string.")

        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise ValueError("Timeout must be a positive finite number.")

    def _validate_endpoint(self) -> None:
        """
        Allow HTTP connections only to loopback addresses.
        This prevents accidental requests to remote servers.
        """
        if not isinstance(self.endpoint, str):
            raise ValueError("Endpoint must be a valid localhost URL.")

        try:
            parsed = urlparse(self.endpoint)
            port = parsed.port
        except ValueError:
            raise ValueError("Invalid AI endpoint URL.") from None

        allowed_hosts = {"127.0.0.1", "localhost", "::1"}

        if parsed.scheme != "http":
            raise ValueError("Only HTTP localhost endpoints are allowed.")

        if parsed.hostname not in allowed_hosts:
            raise ValueError("The AI endpoint must use a localhost address.")

        if parsed.username or parsed.password:
            raise ValueError("Credentials are not allowed in the endpoint URL.")

        if parsed.query or parsed.fragment:
            raise ValueError("Endpoint URLs must not contain a query or fragment.")

        if parsed.path != "/v1/chat/completions":
            raise ValueError("Invalid AI API endpoint path.")

        if port is None or not 1 <= port <= 65535:
            raise ValueError("The endpoint must specify a valid port.")

    def analyze(self, prompt: str) -> str:
        """
        Analyze a prompt using the local AI provider.

        Network communication will be implemented next.
        """
        raise NotImplementedError(
            "Local AI analysis has not been implemented yet."
        )
