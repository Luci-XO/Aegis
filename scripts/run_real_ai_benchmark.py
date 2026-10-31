"""Attack a real AI (Gemini, OpenAI, local Ollama) and measure what Aegis prevents.

Setup: put AEGIS_LLM_PROVIDER, AEGIS_LLM_MODEL and AEGIS_LLM_API_KEY in .env.

Usage:
  python scripts/run_real_ai_benchmark.py                        # the 31 built-in attack/normal scenarios
  python scripts/run_real_ai_benchmark.py --suite corpus         # the 100-email phishing corpus
  python scripts/run_real_ai_benchmark.py --suite my_emails/     # a folder of .eml/.txt/.mbox/.csv/.json
  python scripts/run_real_ai_benchmark.py --suite Takeout.mbox --limit 200
  python scripts/run_real_ai_benchmark.py --modes naive --delay 6

Progress is saved after every run. If it stops (rate limit, HTTP 503), run the
same command again and it resumes. Results appear on the dashboard's
"Real AI arena" page (python -m aegis.web).
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis.agent.llm_client import LLMError, client_from_env
from aegis.eval.real_ai import ARENA_CONFIGS, CALLS_PER_RUN_ESTIMATE, MODES, load_suite, run_arena


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", default="scenarios", help="'scenarios', 'corpus', or a file/folder of emails")
    ap.add_argument("--modes", default=",".join(MODES), help="naive,careful")
    ap.add_argument("--configs", default=",".join(ARENA_CONFIGS))
    ap.add_argument("--limit", type=int, default=0, help="use at most N emails (random sample, seed 7)")
    ap.add_argument("--delay", type=float, default=4.0, help="seconds between runs (free-tier rate limits)")
    ap.add_argument("--run-name", default=None, help="results folder name (reuse it to resume)")
    ap.add_argument("--out", default="results/real_ai")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    a = ap.parse_args()

    try:
        client = client_from_env()
    except LLMError as exc:
        print(f"LLM settings are invalid: {exc}")
        return 2
    if client is None:
        print("Set AEGIS_LLM_PROVIDER, AEGIS_LLM_MODEL and AEGIS_LLM_API_KEY in .env first.")
        return 2
    modes = tuple(m for m in a.modes.split(",") if m)
    configs = tuple(c for c in a.configs.split(",") if c)
    if set(modes) - set(MODES) or set(configs) - set(ARENA_CONFIGS):
        print(f"modes must be from {MODES}, configs from {ARENA_CONFIGS}")
        return 2
    try:
        cases = load_suite(a.suite)
    except FileNotFoundError as exc:
        print(exc)
        return 2
    if not cases:
        print("No usable emails found in that suite.")
        return 2
    if a.limit and len(cases) > a.limit:
        cases = random.Random(7).sample(cases, a.limit)  # noqa: S311 - reproducible sample, not crypto
    run_name = a.run_name or f"{client.model}-{Path(a.suite).stem or a.suite}"
    runs = len(cases) * len(modes) * len(configs)
    print(f"Model: {client.model}   suite: {a.suite} ({len(cases)} emails)   modes: {modes}   configs: {configs}")
    print(f"About {runs} runs and {runs * CALLS_PER_RUN_ESTIMATE} model calls; at {a.delay}s apart this takes "
          f"roughly {runs * (a.delay + 6) / 60:.0f} minutes. Free tiers have daily limits; the run resumes later.")
    if a.suite not in ("scenarios", "corpus"):
        print("Note: these emails will be sent to the model provider. Use synthetic or consented data.")
    if not a.yes and input("Start? [y/N] ").strip().lower() != "y":
        return 1
    path = run_arena(cases, client, Path(a.out), run_name, modes, configs, delay_s=a.delay)
    print(f"\nSaved {path}. Open the dashboard (python -m aegis.web) and click 'Real AI arena'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
