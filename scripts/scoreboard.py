"""Head-to-head scoreboard: your AI vs a real AI (Gemini) on one email corpus.

Runs the whole corpus in one go and prints a single table: how many attacks
each system STOPPED, how many GOT THROUGH, and how many legit emails each one
false-alarmed on. No per-email streaming.

  python scripts/scoreboard.py                                   # your AI only, built-in 100-email corpus
  python scripts/scoreboard.py --corpus aegis/data/email_corpus_500.json
  python scripts/scoreboard.py --corpus aegis/data/email_corpus_500.json --llm --batch 25 --delay 4

"Your AI" is the Aegis email classifier scored with 5-fold grouped-by-template
cross-validation: it is tested only on templates it never trained on, so this
is its honest number. Gemini is zero-shot. With --llm, Gemini classifies the
corpus in batches of --batch emails per call (so 500 emails is ~20 calls, not
500), which is fast and stays under free-tier rate limits.

Gemini needs AEGIS_LLM_* in .env and outbound network, so run --llm on your own
machine. Without --llm it prints your AI's column only and works offline.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis.detect.email_classifier import MALICIOUS, EmailClassifier, sklearn_available
from aegis.eval import email_eval as ev


def tally(emails: list[dict[str, Any]], preds: list[str]) -> dict[str, Any]:
    """Count stopped / got-through / false-alarms. A prediction of ERROR (e.g. an
    answer the model never returned) counts as 'flagged', never as safe."""
    flagged = [p in MALICIOUS or p == "ERROR" for p in preds]
    mal = [e["label"] in MALICIOUS for e in emails]
    legit = [not m for m in mal]
    hard_ph = [e["label"] == "PHISHING" and str(e.get("difficulty", "")).lower() == "hard" for e in emails]

    n_mal = sum(mal)
    stopped = sum(f for f, m in zip(flagged, mal, strict=True) if m)
    n_legit = sum(legit)
    false_alarms = sum(f for f, lg in zip(flagged, legit, strict=True) if lg)
    hard_total = sum(hard_ph)
    hard_stopped = sum(f for f, h in zip(flagged, hard_ph, strict=True) if h)
    correct = sum((f and m) or (not f and not m) for f, m in zip(flagged, mal, strict=True))
    return {
        "malicious": n_mal, "stopped": stopped, "got_through": n_mal - stopped,
        "legit": n_legit, "kept": n_legit - false_alarms, "false_alarms": false_alarms,
        "hard_total": hard_total, "hard_stopped": hard_stopped,
        "accuracy": correct / len(emails) if emails else 0.0,
        "unparsed": preds.count("ERROR"),
    }


def pct(num: int, den: int) -> str:
    return f"{num}/{den} ({(100 * num / den):.0f}%)" if den else "n/a"


def print_board(a_name: str, a: dict[str, Any], b_name: str | None, b: dict[str, Any] | None) -> None:
    cols = [a] if b is None else [a, b]
    names = [a_name] if b is None else [a_name, b_name]
    w = 22
    head = "  ".join(f"{n:>{w}}" for n in names)
    print(f"\n{'':30}{head}")
    print("-" * (30 + len(head) + 2))

    def line(label: str, key: str, den_key: str) -> None:
        cells = "  ".join(f"{pct(c[key], c[den_key]):>{w}}" for c in cols)
        print(f"{label:30}{cells}")

    print(f"{'ATTACKS (phishing + spam)':30}")
    line("  stopped by the filter", "stopped", "malicious")
    line("  GOT THROUGH (missed)", "got_through", "malicious")
    if cols[0]["hard_total"]:
        line("  of those, Hard phishing caught", "hard_stopped", "hard_total")
    print(f"{'LEGITIMATE email':30}")
    line("  kept (correct)", "kept", "legit")
    line("  false alarms", "false_alarms", "legit")
    accs = "  ".join(f"{(100 * c['accuracy']):>{w - 1}.0f}%" for c in cols)
    print(f"{'OVERALL accuracy':30}{accs}")
    if any(c["unparsed"] for c in cols):
        uns = "  ".join(f"{c['unparsed']:>{w}}" for c in cols)
        print(f"{'  (unreadable answers*)':30}{uns}")
        print("\n* answers the model did not return in a usable form; counted as flagged, never as safe.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default=None, help="corpus JSON (default: built-in 100-email corpus)")
    ap.add_argument("--backend", choices=["auto", "stdlib", "sklearn"], default="auto")
    ap.add_argument("--llm", action="store_true", help="also run Gemini/OpenAI (needs AEGIS_LLM_* in .env)")
    ap.add_argument("--batch", type=int, default=25, help="emails per model call when --llm (default 25)")
    ap.add_argument("--delay", type=float, default=4.0, help="seconds between model calls")
    a = ap.parse_args()

    emails = ev.load_corpus(a.corpus)
    backend = "sklearn" if (a.backend == "sklearn" or (a.backend == "auto" and sklearn_available())) else "stdlib"
    print(f"corpus: {len(emails)} emails "
          f"({sum(e['label'] in MALICIOUS for e in emails)} malicious, "
          f"{sum(e['label'] == 'LEGIT' for e in emails)} legit) | your AI backend: {backend}")

    # Your AI: honest grouped cross-validation (never tested on a template it trained on).
    print("scoring your AI (grouped cross-validation)...")
    my_preds, _ = ev.cross_validate(emails, lambda: EmailClassifier(backend, use_headers=True), grouped=True)
    my = tally(emails, my_preds)

    gem_name: str | None = None
    gem: dict[str, Any] | None = None
    gem_preds: list[str] | None = None
    if a.llm:
        from aegis.agent.llm_client import LLMError, client_from_env

        client = client_from_env()
        if client is None:
            print("--llm needs AEGIS_LLM_PROVIDER, AEGIS_LLM_MODEL and AEGIS_LLM_API_KEY in .env")
            return 2
        runs = -(-len(emails) // a.batch)
        print(f"scoring Gemini ({client.model}): {len(emails)} emails in {runs} batches of {a.batch}...")
        try:
            gem_preds, _, _ = ev.llm_judge_batch(emails, client, batch_size=a.batch, delay_s=a.delay)
        except LLMError as exc:
            print(f"\nGemini run stopped: {exc}\nYour AI's column above is still valid.")
            gem_preds = None
        if gem_preds is not None:
            gem_name = f"Gemini ({client.model})"
            gem = tally(emails, gem_preds)

    print_board(f"Your AI ({backend})", my, gem_name, gem)
    if gem is not None and gem["unparsed"] and gem_preds is not None:
        answered = [(e, p) for e, p in zip(emails, gem_preds, strict=True) if p != "ERROR"]
        po = tally([e for e, _ in answered], [p for _, p in answered])
        print(f"\nNote: Gemini returned a usable answer for only {len(answered)}/{len(emails)} emails; the "
              f"{gem['unparsed']} missing ones (likely rate-limited batches) are counted as flagged above, "
              f"which inflates both its 'stopped' and its 'false alarms'.")
        print(f"On just the {len(answered)} it answered ({po['malicious']} malicious, {po['legit']} legit): "
              f"attacks stopped {pct(po['stopped'], po['malicious'])}, "
              f"false alarms {pct(po['false_alarms'], po['legit'])}, accuracy {po['accuracy'] * 100:.0f}%.")
        print("Rerun with gemini-2.5-flash and a smaller --batch (e.g. 10) to get all 500 for a fair comparison.")
    if not a.llm:
        print("\nAdd --llm (with .env set, on a networked machine) to put Gemini in the right-hand column.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
