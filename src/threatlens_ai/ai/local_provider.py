
import json
import math

from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from threatlens_ai.ai.base import BaseAIProvider


class NoRedirectHandler(HTTPRedirectHandler):
    """Prevent HTTP requests from following redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LocalAIProvider(BaseAIProvider):
    """Communicate with a local OpenAI-compatible AI server."""

    MAX_RESPONSE_SIZE = 1024 * 1024  # 1 MiB

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
        """Allow only HTTP endpoints using literal loopback addresses."""

        if not isinstance(self.endpoint, str):
            raise ValueError("Endpoint must be a valid localhost URL.")

        try:
            parsed = urlparse(self.endpoint)
            port = parsed.port
        except ValueError:
            raise ValueError("Invalid AI endpoint URL.") from None

        # Literal loopback addresses only.
        # Avoid accepting 'localhost', whose resolution can be altered.
        allowed_hosts = {"127.0.0.1", "::1"}

        if parsed.scheme != "http":
            raise ValueError("Only HTTP localhost endpoints are allowed.")

        if parsed.hostname not in allowed_hosts:
            raise ValueError("The AI endpoint must use a loopback IP address.")

        if parsed.username or parsed.password:
            raise ValueError("Credentials are not allowed in the endpoint URL.")

        if parsed.query or parsed.fragment:
            raise ValueError("Endpoint URLs must not contain a query or fragment.")

        if parsed.path != "/v1/chat/completions":
            raise ValueError("Invalid AI API endpoint path.")

        if port is None or not 1 <= port <= 65535:
            raise ValueError("The endpoint must specify a valid port.")

    def analyze(self, prompt: str) -> str:
        """Send an explicitly supplied prompt to the local AI server."""

        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Prompt must be a non-empty string.")

        self._validate_endpoint()

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        }

        request_body = json.dumps(payload).encode("utf-8")

        request = Request(
            self.endpoint,
            data=request_body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            # Create an opener that refuses HTTP redirects.
            opener = build_opener(NoRedirectHandler())

            with opener.open(request, timeout=self.timeout) as response:
                response_body = response.read(self.MAX_RESPONSE_SIZE + 1)

        except HTTPError:
            raise RuntimeError(
                "The local AI server returned an HTTP error."
            ) from None

        except (URLError, TimeoutError, OSError):
            raise RuntimeError(
                "Could not communicate with the local AI server."
            ) from None

        if len(response_body) > self.MAX_RESPONSE_SIZE:
            raise RuntimeError("The local AI response exceeded the size limit.")

        try:
            result = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError(
                "The local AI server returned an invalid JSON response."
            ) from None

        try:
            content = result["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise RuntimeError(
                "The local AI server returned an unexpected response structure."
            ) from None

        if not isinstance(content, str) or not content.strip():
            raise RuntimeError(
                "The local AI server returned an empty or invalid response."
            )

        return content
