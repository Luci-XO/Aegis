"""Evaluate email threat detectors on an email corpus.

Usage:
  python scripts/eval_email_classifier.py                  # built-in 100-email corpus
  python scripts/eval_email_classifier.py --corpus aegis/data/email_corpus_500.json
  python scripts/eval_email_classifier.py --backend sklearn
  python scripts/eval_email_classifier.py --json results/email_eval.json

Build the 500-email corpus first with: python scripts/build_corpus_500.py

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
    ap.add_argument("--corpus", default=None,
                    help="path to a corpus JSON (default: built-in 100-email corpus). "
                         "Build the 500-email corpus with scripts/build_corpus_500.py")
    ap.add_argument("--json", help="write full results to this path")
    a = ap.parse_args()

    emails = ev.load_corpus(a.corpus)
    backend = a.backend
    if backend == "auto":
        backend = "sklearn" if sklearn_available() else "stdlib"
    print(f"corpus: {len(emails)} emails, {len({e['family'] for e in emails})} template families; "
          f"classifier backend: {backend}\n")

    results: dict = {"backend": backend}
    lines = ["| Detector | Evaluation | Precision | Recall | F1 | 3-class acc | FPR legit | FPR tricky | FP / FN |",
             "|---|---|---|---|---|---|---|---|---|"]

    n = len(emails)
    for name, fn in [("auth-header rule", ev.auth_rule), ("red-flag rules (text)", ev.redflag_rule),
                     ("injection rules-v1", ev.injection_rule)]:
        s = ev.score(emails, [fn(e) for e in emails])
        results[name] = s
        lines.append(row(name, f"all {n} (no training)", s))

    for headers in (False, True):
        label = "classifier (text+headers)" if headers else "classifier (text)"
        for grouped in (False, True):
            split = "5-fold grouped by template" if grouped else "5-fold random (leaky)"
            _, s = ev.cross_validate(emails, lambda h=headers: EmailClassifier(backend, use_headers=h),
                                     grouped=grouped)
            results[f"{label} / {split}"] = s
            lines.append(row(label, split, s))

    # Hybrid: classifier OR >=2 independent text red flags. Honest number is the
    # grouped split; text-only so the lift does not lean on the header artifact.
    for headers in (False, True):
        label = "hybrid (text+headers+rules)" if headers else "hybrid (text+rules)"
        split = "5-fold grouped by template"
        _, s = ev.cross_validate(
            emails, lambda h=headers: EmailClassifier(backend, use_headers=h, use_rules=True), grouped=True)
        results[f"{label} / {split}"] = s
        lines.append(row(label, split, s))

    print("\n".join(lines))
    best = results["classifier (text) / 5-fold grouped by template"]
    print(f"\nGrouped-CV text classifier misclassified (binary): {best['binary_errors'] or 'none'}")
    if a.json:
        Path(a.json).parent.mkdir(parents=True, exist_ok=True)
        Path(a.json).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"wrote {a.json}")

    clf = EmailClassifier(backend).fit(emails, [e["label"] for e in emails])
    ex = next((e for e in emails if e["label"] == "PHISHING"), emails[0])
    print(f"\nExample explanation (model trained on all {len(emails)}, shown for {ex['id']}):\n"
          f"  {clf.predict([ex])[0].explain()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
