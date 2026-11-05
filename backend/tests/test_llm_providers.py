"""Provider tests with httpx mocked: no real network calls are made."""
import httpx
import pytest

from app.config import get_settings
from app.services.llm import LLMError, LLMNotConfigured, get_provider
from app.services.llm import gemini_provider
from app.services.llm.gemini_provider import GeminiProvider


def fake_post(status=200, json_body=None, capture=None):
    def _post(url, json=None, headers=None, timeout=None):
        if capture is not None:
            capture.update(url=url, json=json, headers=headers)
        request = httpx.Request("POST", url)
        return httpx.Response(status, json=json_body if json_body is not None else {}, request=request)
    return _post


GOOD = {"candidates": [{"content": {"parts": [{"text": "## 1. Incident Summary\nok"}]}, "finishReason": "STOP"}]}


def test_gemini_success_and_request_shape(monkeypatch):
    seen = {}
    monkeypatch.setattr(gemini_provider.httpx, "post", fake_post(200, GOOD, seen))
    text = GeminiProvider("SECRET-KEY", "gemini-test").generate("sys prompt", "user prompt")
    assert text.startswith("## 1.")
    assert seen["url"].endswith("/models/gemini-test:generateContent")
    assert "SECRET-KEY" not in seen["url"] and seen["headers"]["x-goog-api-key"] == "SECRET-KEY"
    assert seen["json"]["systemInstruction"]["parts"][0]["text"] == "sys prompt"
    assert seen["json"]["contents"][0]["parts"][0]["text"] == "user prompt"


def test_gemini_ignores_thought_parts(monkeypatch):
    body = {"candidates": [{"content": {"parts": [{"text": "hidden", "thought": True}, {"text": "answer"}]}}]}
    monkeypatch.setattr(gemini_provider.httpx, "post", fake_post(200, body))
    assert GeminiProvider("k", "m").generate("s", "u") == "answer"


@pytest.mark.parametrize("status,fragment", [(429, "rate limit"), (404, "LLM_MODEL"), (403, "rejected")])
def test_gemini_http_errors_give_actionable_messages_without_leaking_key(monkeypatch, status, fragment):
    monkeypatch.setattr(gemini_provider.httpx, "post", fake_post(status, {"error": {"message": "SECRET-KEY"}}))
    with pytest.raises(LLMError) as exc:
        GeminiProvider("SECRET-KEY", "gemini-x").generate("s", "u")
    assert fragment in str(exc.value) and "SECRET-KEY" not in str(exc.value)


def test_gemini_blocked_or_empty_responses(monkeypatch):
    monkeypatch.setattr(gemini_provider.httpx, "post",
                        fake_post(200, {"promptFeedback": {"blockReason": "SAFETY"}}))
    with pytest.raises(LLMError, match="SAFETY"):
        GeminiProvider("k", "m").generate("s", "u")
    monkeypatch.setattr(gemini_provider.httpx, "post",
                        fake_post(200, {"candidates": [{"content": {"parts": []}, "finishReason": "MAX_TOKENS"}]}))
    with pytest.raises(LLMError, match="MAX_TOKENS"):
        GeminiProvider("k", "m").generate("s", "u")


def test_gemini_network_error_becomes_llm_error(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectTimeout("t")
    monkeypatch.setattr(gemini_provider.httpx, "post", boom)
    with pytest.raises(LLMError, match="ConnectTimeout"):
        GeminiProvider("k", "m").generate("s", "u")


def configure(monkeypatch, **env):
    for key in ("LLM_PROVIDER", "GEMINI_API_KEY", "ANTHROPIC_API_KEY", "LLM_MODEL"):
        monkeypatch.setenv(key, env.get(key, ""))
    get_settings.cache_clear()


def test_provider_selection(monkeypatch):
    configure(monkeypatch, LLM_PROVIDER="gemini", GEMINI_API_KEY="abc")
    p = get_provider()
    assert (p.name, p.model) == ("gemini", "gemini-3.8-flash")
    configure(monkeypatch, LLM_PROVIDER="gemini", GEMINI_API_KEY="abc", LLM_MODEL="gemini-3.5-flash-lite")
    assert get_provider().model == "gemini-3.5-flash-lite"
    configure(monkeypatch, LLM_PROVIDER="anthropic", ANTHROPIC_API_KEY="abc")
    assert get_provider().name == "anthropic"
    with pytest.raises(LLMNotConfigured, match="GEMINI_API_KEY"):
        configure(monkeypatch, LLM_PROVIDER="gemini")
        get_provider()
    with pytest.raises(LLMNotConfigured, match="Unsupported"):
        configure(monkeypatch, LLM_PROVIDER="foo", GEMINI_API_KEY="abc")
        get_provider()
    get_settings.cache_clear()
