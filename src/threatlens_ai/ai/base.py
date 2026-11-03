
from abc import ABC, abstractmethod


class BaseAIProvider(ABC):
    """
    Common interface for all ThreatLens AI providers.

    Local and cloud AI providers must implement
    the analyze() method.
    """

    @abstractmethod
    def analyze(self, prompt: str) -> str:
        """
        Analyze a prompt and return the AI-generated response.

        Args:
            prompt: Security-related analysis instructions.

        Returns:
            AI-generated response as a string.
        """
        pass
