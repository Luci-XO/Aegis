"""Provider-independent chat client (standard library only).

`OpenAICompatibleClient` speaks the widely used `/chat/completions` format,
which covers OpenAI-compatible hosted APIs and local servers such as Ollama
(`http://localhost:11434/v1`). Configuration comes from environment variables;
see `.env.example`. No key is ever hard-coded or logged.

The security core never imports this module.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol


class LLMError(RuntimeError):
    pass


class ChatClient(Protocol):
    model: str
    temperature: float

    def complete(self, messages: list[dict[str, str]]) -> str: ...


@dataclass
class OpenAICompatibleClient:
    base_url: str
    model: str
    api_key: str | None = None
    temperature: float = 0.0
    timeout_s: float = 60.0
    max_tokens: int = 800

    def complete(self, messages: list[dict[str, str]]) -> str:
        if not self.base_url.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            raise LLMError("base_url must be https, or http on localhost")
        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(  # noqa: S310 - scheme checked above
            self.base_url.rstrip("/") + "/chat/completions", data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:  # noqa: S310
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise LLMError(f"LLM request failed: {type(exc).__name__}") from None
        try:
            return str(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError):
            raise LLMError("unexpected LLM response shape") from None


def client_from_env(env: dict[str, str] | None = None) -> OpenAICompatibleClient | None:
    """Return a client if AEGIS_LLM_PROVIDER is set, otherwise None (use the scripted agent)."""
    e = os.environ if env is None else env
    provider = (e.get("AEGIS_LLM_PROVIDER") or "").strip().lower()
    if not provider:
        return None
    defaults = {"openai": "https://api.openai.com/v1", "ollama": "http://localhost:11434/v1"}
    base = e.get("AEGIS_LLM_BASE_URL") or defaults.get(provider)
    model = e.get("AEGIS_LLM_MODEL")
    if not base or not model:
        raise LLMError("AEGIS_LLM_BASE_URL and AEGIS_LLM_MODEL are required for this provider")
    return OpenAICompatibleClient(
        base_url=base, model=model, api_key=e.get("AEGIS_LLM_API_KEY") or None,
        temperature=float(e.get("AEGIS_LLM_TEMPERATURE", "0") or 0),
    )
