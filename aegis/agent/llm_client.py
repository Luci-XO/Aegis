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


class _TransientError(LLMError):
    """A failure worth retrying (rate limit, overload, network)."""


TRANSIENT_HTTP = frozenset({429, 500, 502, 503, 504})


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
    retries: int = 4  # extra attempts for temporary failures (429, 500, 502, 503, 504, network)
    backoff_s: float = 5.0  # wait backoff_s, 2x, 4x ... between attempts

    def complete(self, messages: list[dict[str, str]]) -> str:
        """Send one chat request, retrying temporary failures with exponential backoff."""
        import time

        for attempt in range(self.retries + 1):
            try:
                return self._complete_once(messages)
            except _TransientError as exc:
                if attempt == self.retries:
                    raise LLMError(str(exc)) from None
                time.sleep(self.backoff_s * (2 ** attempt))
        raise LLMError("unreachable")  # pragma: no cover

    def _complete_once(self, messages: list[dict[str, str]]) -> str:
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
        except urllib.error.HTTPError as exc:
            hint = {400: "bad request or model name", 401: "API key rejected",
                    403: "API key lacks permission", 404: "unknown model or base URL",
                    429: "rate limited or out of quota", 503: "model overloaded or unavailable, try later",
                    }.get(exc.code, "server error")
            msg = f"LLM request failed: HTTP {exc.code} ({hint})"
            if exc.code in TRANSIENT_HTTP:
                raise _TransientError(msg) from None
            raise LLMError(msg) from None
        except (urllib.error.URLError, TimeoutError) as exc:
            raise _TransientError(f"LLM request failed: {type(exc).__name__}") from None
        except json.JSONDecodeError as exc:
            raise LLMError(f"LLM request failed: {type(exc).__name__}") from None
        try:
            return str(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError):
            raise LLMError("unexpected LLM response shape") from None


PROVIDER_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "ollama": "http://localhost:11434/v1",
    # Gemini's OpenAI-compatible endpoint: https://ai.google.dev/gemini-api/docs/openai
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
}


def load_env_file(path: str = ".env") -> dict[str, str]:
    """Read KEY=VALUE lines from a .env file without overriding real environment variables.

    Minimal on purpose (no dependency on python-dotenv): blank lines and lines
    starting with '#' are ignored, and surrounding quotes are stripped. Returns
    the merged view; os.environ itself is not modified.
    """
    merged: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                if key:
                    merged[key] = value
    except FileNotFoundError:
        pass
    merged.update({k: v for k, v in os.environ.items()})
    return merged


def client_from_env(env: dict[str, str] | None = None) -> OpenAICompatibleClient | None:
    """Return a client if AEGIS_LLM_PROVIDER is set, otherwise None (use the scripted agent).

    With env=None, settings come from the process environment plus a .env file
    in the current directory (real environment variables win).
    """
    e = load_env_file() if env is None else env
    provider = (e.get("AEGIS_LLM_PROVIDER") or "").strip().lower()
    if not provider:
        return None
    defaults = PROVIDER_BASE_URLS
    base = e.get("AEGIS_LLM_BASE_URL") or defaults.get(provider)
    model = e.get("AEGIS_LLM_MODEL")
    if not base or not model:
        raise LLMError("AEGIS_LLM_BASE_URL and AEGIS_LLM_MODEL are required for this provider")
    return OpenAICompatibleClient(
        base_url=base, model=model, api_key=e.get("AEGIS_LLM_API_KEY") or None,
        temperature=float(e.get("AEGIS_LLM_TEMPERATURE", "0") or 0),
    )
