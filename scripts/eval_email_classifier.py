"""Evaluate email threat detectors on the 100-email corpus.

Usage:
  python scripts/eval_email_classifier.py                  # rules + classifier (stdlib or sklearn)
  python scripts/eval_email_classifier.py --backend sklearn
  python scripts/eval_email_classifier.py --llm --delay 4  # also Gemini/OpenAI judge (needs .env)
  python scripts/eval_email_classifier.py --json results/email_eval.json

The grouped cross-validation row is the honest number for a learned model:
whole template families are held out, so the model is tested on templates it
never saw during training.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis.detect.email_classifier import EmailClassifier, sklearn_available
from aegis.eval import email_eval as ev


def row(name: str, split: str, s: dict) -> str:
    m = s["malicious"]
    f = lambda x: "n/a" if x is None else f"{x:.2f}"  # noqa: E731
    return (f"| {name} | {split} | {f(m['precision'])} | {f(m['recall'])} | {f(m['f1'])} | "
            f"{s['accuracy_3class']:.2f} | {f(s['fpr_legit'])} | {f(s['fpr_tricky_legit'])} | "
            f"{m['fp']} / {m['fn']} |")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["auto", "stdlib", "sklearn"], default="auto")
    ap.add_argument("--llm", action="store_true", help="also run an LLM judge (AEGIS_LLM_* in env or .env)")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between LLM calls (free-tier rate limits)")
    ap.add_argument("--json", help="write full results to this path")
    a = ap.parse_args()

    emails = ev.load_corpus()
    backend = a.backend
    if backend == "auto":
        backend = "sklearn" if sklearn_available() else "stdlib"
    print(f"corpus: {len(emails)} emails, {len({e['family'] for e in emails})} template families; "
          f"classifier backend: {backend}\n")

    results: dict = {"backend": backend}
    lines = ["| Detector | Evaluation | Precision | Recall | F1 | 3-class acc | FPR legit | FPR tricky | FP / FN |",
             "|---|---|---|---|---|---|---|---|---|"]

    for name, fn in [("auth-header rule", ev.auth_rule), ("red-flag rules (text)", ev.redflag_rule),
                     ("injection rules-v1", ev.injection_rule)]:
        s = ev.score(emails, [fn(e) for e in emails])
        results[name] = s
        lines.append(row(name, "all 100 (no training)", s))

    for headers in (False, True):
        label = "classifier (text+headers)" if headers else "classifier (text)"
        for grouped in (False, True):
            split = "5-fold grouped by template" if grouped else "5-fold random (leaky)"
            _, s = ev.cross_validate(emails, lambda h=headers: EmailClassifier(backend, use_headers=h),
                                     grouped=grouped)
            results[f"{label} / {split}"] = s
            lines.append(row(label, split, s))

    if a.llm:
        from aegis.agent.llm_client import client_from_env

        client = client_from_env()
        if client is None:
            print("--llm needs AEGIS_LLM_PROVIDER, AEGIS_LLM_MODEL and AEGIS_LLM_API_KEY (env or .env)")
            return 2
        print(f"LLM judge: {client.model} via {client.base_url}")
        _, s, details = ev.llm_judge(emails, client, delay_s=a.delay)
        results["llm judge"] = {**s, "model": client.model, "details": details}
        lines.append(row(f"LLM judge ({client.model})", "all 100 (zero-shot)", s))

    print("\n".join(lines))
    best = results["classifier (text) / 5-fold grouped by template"]
    print(f"\nGrouped-CV text classifier misclassified (binary): {best['binary_errors'] or 'none'}")
    if a.json:
        Path(a.json).parent.mkdir(parents=True, exist_ok=True)
        Path(a.json).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"wrote {a.json}")

    clf = EmailClassifier(backend).fit(emails, [e["label"] for e in emails])
    ex = next(e for e in emails if e["id"] == "E002")
    print(f"\nExample explanation (model trained on all 100, shown for E002):\n  {clf.predict([ex])[0].explain()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
