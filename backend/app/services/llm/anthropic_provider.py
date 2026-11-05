from __future__ import annotations

import httpx

from app.services.llm.base import LLMError

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str, timeout: float = 60.0, max_tokens: int = 2000):
        self._api_key = api_key
        self.model = model
        self._timeout = timeout
        self._max_tokens = max_tokens

    def generate(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "max_tokens": self._max_tokens,
            "temperature": 0.2,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
        }
        try:
            response = httpx.post(API_URL, json=payload, headers=headers, timeout=self._timeout)
            response.raise_for_status()
            blocks = response.json()["content"]
            text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
        except httpx.HTTPStatusError as exc:  # never include headers/body: they may echo secrets
            raise LLMError(f"LLM API returned HTTP {exc.response.status_code}") from None
        except httpx.HTTPError as exc:
            raise LLMError(f"LLM API request failed ({type(exc).__name__})") from None
        except (KeyError, ValueError, TypeError):
            raise LLMError("LLM API returned an unexpected response format") from None
        if not text:
            raise LLMError("LLM API returned an empty response")
        return text
