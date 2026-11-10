"""Scoreboard: how your AI does on one email corpus, scored honestly.

Runs the whole corpus in one go and prints a single table: how many attacks
the filter STOPPED, how many GOT THROUGH, and how many legit emails it
false-alarmed on. No per-email streaming.

  python scripts/scoreboard.py                                   # built-in 100-email corpus
  python scripts/scoreboard.py --corpus aegis/data/email_corpus_500.json
  python scripts/scoreboard.py --corpus aegis/data/email_corpus_500.json --json results/scoreboard.json

"Your AI" is the Aegis email classifier scored with 5-fold grouped-by-template
cross-validation: it is tested only on templates it never trained on, so this
is its honest number. Everything here runs offline with no API keys.
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
    """Count stopped / got-through / false-alarms. A prediction that is not a
    usable label counts as 'flagged', never as safe."""
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
    by_diff: dict[str, dict[str, int]] = {}
    for e, f, m in zip(emails, flagged, mal, strict=True):
        if not m:
            continue
        d = str(e.get("difficulty", "") or "unknown").capitalize()
        slot = by_diff.setdefault(d, {"malicious": 0, "stopped": 0})
        slot["malicious"] += 1
        slot["stopped"] += int(f)
    return {
        "malicious": n_mal, "stopped": stopped, "got_through": n_mal - stopped,
        "legit": n_legit, "kept": n_legit - false_alarms, "false_alarms": false_alarms,
        "hard_total": hard_total, "hard_stopped": hard_stopped,
        "accuracy": correct / len(emails) if emails else 0.0,
        "by_difficulty": by_diff,
    }


def pct(num: int, den: int) -> str:
    return f"{num}/{den} ({(100 * num / den):.0f}%)" if den else "n/a"


def print_board(a_name: str, a: dict[str, Any]) -> None:
    w = 22
    head = f"{a_name:>{w}}"
    print(f"\n{'':30}{head}")
    print("-" * (30 + len(head) + 2))

    def line(label: str, key: str, den_key: str) -> None:
        print(f"{label:30}{pct(a[key], a[den_key]):>{w}}")

    print(f"{'ATTACKS (phishing + spam)':30}")
    line("  stopped by the filter", "stopped", "malicious")
    line("  GOT THROUGH (missed)", "got_through", "malicious")
    if a["hard_total"]:
        line("  of those, Hard phishing caught", "hard_stopped", "hard_total")
    print(f"{'LEGITIMATE email':30}")
    line("  kept (correct)", "kept", "legit")
    line("  false alarms", "false_alarms", "legit")
    diffs = [d for d in ("Easy", "Medium", "Hard") if d in a["by_difficulty"]]
    if diffs:
        print(f"{'ATTACKS stopped by difficulty':30}")
        for d in diffs:
            slot = a["by_difficulty"].get(d, {})
            print(f"{'  ' + d:30}{pct(slot.get('stopped', 0), slot.get('malicious', 0)):>{w}}")
    print(f"{'OVERALL accuracy':30}{(100 * a['accuracy']):>{w - 1}.0f}%")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default=None, help="corpus JSON (default: built-in 100-email corpus)")
    ap.add_argument("--backend", choices=["auto", "stdlib", "sklearn"], default="auto")
    ap.add_argument("--json", dest="json_out", default=None,
                    help="also write the scoreboard to this JSON path (e.g. results/scoreboard.json, "
                         "which the dashboard's Scoreboard page reads)")
    a = ap.parse_args()

    emails = ev.load_corpus(a.corpus)
    backend = "sklearn" if (a.backend == "sklearn" or (a.backend == "auto" and sklearn_available())) else "stdlib"
    print(f"corpus: {len(emails)} emails "
          f"({sum(e['label'] in MALICIOUS for e in emails)} malicious, "
          f"{sum(e['label'] == 'LEGIT' for e in emails)} legit) | your AI backend: {backend}")

    # Your AI: honest grouped cross-validation (never tested on a template it trained on).
    # The hybrid red-flag rules stay off: they were written while reading these corpora,
    # so turning them on here would inflate the score.
    print("scoring your AI (grouped cross-validation)...")
    my_preds, _ = ev.cross_validate(
        emails, lambda: EmailClassifier(backend, use_headers=True), grouped=True)
    my = tally(emails, my_preds)

    print_board(f"Your AI ({backend})", my)

    if a.json_out:
        import json

        out = {
            "corpus": a.corpus or "built-in 100-email corpus",
            "total": len(emails),
            "malicious": sum(e["label"] in MALICIOUS for e in emails),
            "legit": sum(e["label"] == "LEGIT" for e in emails),
            "your_ai": {"name": f"Your AI ({backend})", **my},
        }
        Path(a.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.json_out).write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"\nwrote {a.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
