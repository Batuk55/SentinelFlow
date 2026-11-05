"""Provider-agnostic LLM interface. To add a provider, implement `generate` and register it below."""
from __future__ import annotations

from typing import Protocol

from app.config import get_settings


class LLMError(Exception):
    """The LLM call failed (network, HTTP error, malformed response)."""


class LLMNotConfigured(LLMError):
    """No usable provider/API key is configured."""


class LLMProvider(Protocol):
    name: str
    model: str

    def generate(self, system: str, user: str) -> str: ...


DEFAULT_MODELS = {"anthropic": "claude-sonnet-4-6", "gemini": "gemini-3.8-flash"}


def get_provider() -> LLMProvider:
    """Build the configured provider, or raise LLMNotConfigured so the caller can use the fallback."""
    settings = get_settings()
    provider = settings.llm_provider.lower().strip()
    model = settings.llm_model.strip() or DEFAULT_MODELS.get(provider, "")
    if provider == "anthropic":
        if not settings.anthropic_api_key.strip():
            raise LLMNotConfigured("ANTHROPIC_API_KEY is not set")
        from app.services.llm.anthropic_provider import AnthropicProvider

        return AnthropicProvider(settings.anthropic_api_key.strip(), model)
    if provider == "gemini":
        if not settings.gemini_api_key.strip():
            raise LLMNotConfigured("GEMINI_API_KEY is not set")
        from app.services.llm.gemini_provider import GeminiProvider

        return GeminiProvider(settings.gemini_api_key.strip(), model)
    raise LLMNotConfigured(f"Unsupported LLM_PROVIDER '{settings.llm_provider}' (use 'gemini' or 'anthropic')")
