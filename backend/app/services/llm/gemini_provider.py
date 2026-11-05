from __future__ import annotations

import httpx

from app.services.llm.base import LLMError

BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiProvider:
    """Google Gemini via the REST generateContent endpoint (works with free AI Studio keys)."""

    name = "gemini"

    def __init__(self, api_key: str, model: str, timeout: float = 90.0, max_output_tokens: int = 4096):
        self._api_key = api_key
        self.model = model
        self._timeout = timeout
        self._max_output_tokens = max_output_tokens

    def generate(self, system: str, user: str) -> str:
        payload = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            # Generous limit: some Gemini models spend part of the budget on internal reasoning.
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": self._max_output_tokens},
        }
        # The key goes in a header, not the URL, so it cannot leak into logs or error messages.
        headers = {"x-goog-api-key": self._api_key, "content-type": "application/json"}
        url = f"{BASE_URL}/{self.model}:generateContent"
        try:
            response = httpx.post(url, json=payload, headers=headers, timeout=self._timeout)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            hint = {
                400: " (check the request or API key)",
                403: " (API key rejected or not allowed for this model)",
                404: f" (model '{self.model}' not found; set LLM_MODEL to a model listed in AI Studio)",
                429: " (free-tier rate limit reached; wait a minute and retry)",
            }.get(status, "")
            raise LLMError(f"Gemini API returned HTTP {status}{hint}") from None
        except httpx.HTTPError as exc:
            raise LLMError(f"Gemini API request failed ({type(exc).__name__})") from None
        except ValueError:
            raise LLMError("Gemini API returned invalid JSON") from None

        try:
            candidate = data["candidates"][0]
            parts = candidate.get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts if not p.get("thought")).strip()
        except (KeyError, IndexError, TypeError, AttributeError):
            reason = (data.get("promptFeedback") or {}).get("blockReason") if isinstance(data, dict) else None
            raise LLMError(f"Gemini returned no candidates{f' (blocked: {reason})' if reason else ''}") from None
        if not text:
            raise LLMError(f"Gemini returned an empty response (finishReason: {candidate.get('finishReason')})")
        return text
