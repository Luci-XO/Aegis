"""Evaluation of email threat detectors on the 100-email corpus.

Compares, on identical data:

  auth-header rule      malicious if SPF or DMARC is not "pass"
  red-flag rules        malicious if any text red flag fires (no headers)
  injection rules       Aegis rules-v1 prompt-injection detector (a different task, for reference)
  classifier (text)     TF-IDF + logistic regression on subject/body/attachment names
  classifier (+headers) the same plus SPF/DKIM/DMARC, Reply-To and extension tokens

Learned models are scored with 5-fold cross-validation in two ways:
  random     emails shuffled into folds (near-duplicate templates leak across folds)
  grouped    whole template families kept together, so the model is tested on
             templates it never saw. This is the number to report.

Metrics: per-class precision/recall/F1, binary "malicious" (PHISHING or SPAM)
precision/recall/F1, false-positive rate on all legit email and on the 10
tricky-legit emails.
"""

from __future__ import annotations

import json
import random
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from importlib import resources
from typing import Any

from aegis.detect.email_classifier import LABELS, MALICIOUS, EmailClassifier, red_flags
from aegis.detect.rules import RuleDetector

Email = Mapping[str, Any]


def load_corpus(path: str | None = None) -> list[dict[str, Any]]:
    """Load the email corpus. With no path, the built-in 100-email corpus;
    with a path, any JSON in the same schema (e.g. the 500-email corpus built
    by scripts/build_corpus_500.py)."""
    from pathlib import Path

    src = Path(path).read_text("utf-8") if path else (
        resources.files("aegis") / "data" / "email_corpus.json").read_text("utf-8")
    emails: list[dict[str, Any]] = json.loads(src)["emails"]
    return emails


# ---------------------------------------------------------------- metrics

def _prf(tp: int, fp: int, fn: int) -> dict[str, float | None]:
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f = (2 * p * r / (p + r) if p and r else 0.0) if p is not None and r is not None else None
    return {"precision": None if p is None else round(p, 4), "recall": None if r is None else round(r, 4),
            "f1": None if f is None else round(f, 4)}


def score(emails: Sequence[Email], predicted: Sequence[str]) -> dict[str, Any]:
    gold = [e["label"] for e in emails]
    per_class = {}
    for c in LABELS:
        tp = sum(g == c and p == c for g, p in zip(gold, predicted, strict=True))
        fp = sum(g != c and p == c for g, p in zip(gold, predicted, strict=True))
        fn = sum(g == c and p != c for g, p in zip(gold, predicted, strict=True))
        per_class[c] = {**_prf(tp, fp, fn), "support": gold.count(c)}
    gm = [g in MALICIOUS for g in gold]
    pm = [p in MALICIOUS or p == "ERROR" for p in predicted]
    tp = sum(a and b for a, b in zip(gm, pm, strict=True))
    fp = sum((not a) and b for a, b in zip(gm, pm, strict=True))
    fn = sum(a and not b for a, b in zip(gm, pm, strict=True))
    legit = [i for i, e in enumerate(emails) if e["label"] == "LEGIT"]
    tricky = [i for i, e in enumerate(emails) if e.get("tricky")]
    wrong = [e["id"] for e, g, p in zip(emails, gm, pm, strict=True) if g != p]
    return {
        "n": len(emails),
        "accuracy_3class": round(sum(g == p for g, p in zip(gold, predicted, strict=True)) / len(gold), 4),
        "malicious": {**_prf(tp, fp, fn), "tp": tp, "fp": fp, "fn": fn},
        "fpr_legit": round(sum(pm[i] for i in legit) / len(legit), 4) if legit else None,
        "fpr_tricky_legit": round(sum(pm[i] for i in tricky) / len(tricky), 4) if tricky else None,
        "per_class": per_class,
        "binary_errors": wrong,
        "errors_unparsed": predicted.count("ERROR"),
    }


# ---------------------------------------------------------------- rule baselines

def auth_rule(e: Email) -> str:
    a = e.get("auth") or {}
    return "PHISHING" if a.get("spf") != "pass" or a.get("dmarc") != "pass" else "LEGIT"


def redflag_rule(e: Email) -> str:
    text_only = [f for f in red_flags(e)
                 if not f.startswith(("authentication failed", "Reply-To", "risky attachment"))]
    return "PHISHING" if text_only else "LEGIT"


def injection_rule(e: Email, threshold: float = 0.5) -> str:
    det = RuleDetector()
    s = max(det.analyze(e["subject"]).score, det.analyze(e["body"]).score)
    return "PHISHING" if s >= threshold else "LEGIT"


# ---------------------------------------------------------------- cross-validation

def folds(emails: Sequence[Email], k: int, grouped: bool, seed: int = 7) -> list[list[int]]:
    """Return k lists of test indices. Grouped folds keep each template family
    together and are balanced by label; random folds are stratified by label."""
    rng = random.Random(seed)  # noqa: S311 - seeded split, not crypto
    out: list[list[int]] = [[] for _ in range(k)]
    if grouped:
        fam: dict[str, list[int]] = defaultdict(list)
        for i, e in enumerate(emails):
            fam[e["family"]].append(i)
        by_label: dict[str, list[list[int]]] = defaultdict(list)
        for idx in fam.values():
            by_label[emails[idx[0]]["label"]].append(idx)
        for groups in by_label.values():
            rng.shuffle(groups)
            groups.sort(key=len, reverse=True)
            for g in groups:  # greedy: put each family into the currently smallest fold
                min(out, key=len).extend(g)
    else:
        by_label_i: dict[str, list[int]] = defaultdict(list)
        for i, e in enumerate(emails):
            by_label_i[e["label"]].append(i)
        for idx in by_label_i.values():
            rng.shuffle(idx)
            for j, i in enumerate(idx):
                out[j % k].append(i)
    return out


def cross_validate(emails: Sequence[Email], make: Callable[[], EmailClassifier], k: int = 5,
                   grouped: bool = True) -> tuple[list[str], dict[str, Any]]:
    preds: list[str | None] = [None] * len(emails)
    for test in folds(emails, k, grouped):
        test_set = set(test)
        train = [i for i in range(len(emails)) if i not in test_set]
        if len({emails[i]["label"] for i in train}) < 2:
            raise ValueError("a training fold contains only one class")
        clf = make().fit([emails[i] for i in train], [emails[i]["label"] for i in train])
        for i, v in zip(test, clf.predict([emails[i] for i in test]), strict=True):
            preds[i] = v.label
    final = [p or "ERROR" for p in preds]
    return final, score(emails, final)
