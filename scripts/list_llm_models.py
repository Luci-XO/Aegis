"""List the models your LLM key can use (reads AEGIS_LLM_* from the environment or .env).

    python scripts/list_llm_models.py

Copy one of the printed ids into AEGIS_LLM_MODEL in .env. The key is never printed.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis.agent.llm_client import PROVIDER_BASE_URLS, load_env_file


def main() -> int:
    env = load_env_file()
    provider = (env.get("AEGIS_LLM_PROVIDER") or "").strip().lower()
    base = env.get("AEGIS_LLM_BASE_URL") or PROVIDER_BASE_URLS.get(provider)
    key = env.get("AEGIS_LLM_API_KEY")
    if not base:
        print("Set AEGIS_LLM_PROVIDER (e.g. gemini) in .env first.")
        return 2
    req = urllib.request.Request(base.rstrip("/") + "/models",  # noqa: S310 - configured provider URL
                                 headers={"Authorization": f"Bearer {key}"} if key else {})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310
            data = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}: the key was rejected or lacks access (401/403), or the base URL is wrong (404).")
        return 1
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"Could not reach {base}: {type(exc).__name__}")
        return 1
    ids = sorted(str(m.get("id", "")).removeprefix("models/") for m in data.get("data", []))
    chat = [i for i in ids if any(w in i for w in ("flash", "pro", "gpt", "llama"))
            and not any(w in i for w in ("embed", "image", "tts", "audio", "live", "veo", "imagen"))]
    print(f"{len(ids)} models available; likely chat models:")
    for i in chat or ids:
        print("  ", i)
    print(f"\nCurrently configured AEGIS_LLM_MODEL={env.get('AEGIS_LLM_MODEL') or '(empty)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
