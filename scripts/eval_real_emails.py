"""Before/after test of the Aegis email classifier on real email.

Uses the Kaggle dataset "phishing-email-dataset-nazario-5-and-trec07"
(Nazario_5 phishing + Enron legit, and the TREC 2007 spam/ham set).

Download it first on your machine:

    pip install kagglehub scikit-learn
    python -c "import kagglehub; print(kagglehub.dataset_download('rohansood98/phishing-email-dataset-nazario-5-and-trec07'))"

That prints a folder. This script looks in the default kagglehub cache; if
yours is elsewhere, pass it:

    python scripts/eval_real_emails.py --data-dir "C:/path/to/versions/1"

The real emails are never copied into the repo: the script reads them straight
from that folder. scikit-learn is strongly recommended; the pure-Python
fallback is far too slow for the 50k-email TREC set.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis.detect.email_classifier import MALICIOUS, EmailClassifier, sklearn_available
from aegis.eval import email_eval as ev

csv.field_size_limit(10**9)
SEED = 0
_ADDR = re.compile(r"[\w.+-]+@([\w-]+\.)+[\w-]+")
# The legit half of Nazario_5 is Enron corporate mail; mask that source tell so
# the model must learn phishing, not "mentions Enron".
_ENRON = re.compile(r"\b(enron\w*|ect|hou|corp)\b", re.I)


def _mask(text: str) -> str:
    return _ENRON.sub(" ", _ADDR.sub(" ", text or ""))


def _default_dir() -> Path:
    return (Path.home() / ".cache" / "kagglehub" / "datasets" / "rohansood98"
            / "phishing-email-dataset-nazario-5-and-trec07" / "versions" / "1")


def _dedupe(emails: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out = []
    for e in emails:
        text = (e["subject"] + "\n" + e["body"]).strip()
        key = hashlib.sha1(text.lower().encode()).hexdigest()  # noqa: S324  dedup only, not security
        if text and key not in seen:
            seen.add(key)
            out.append(e)
    return out


def _load(path: Path, to_email) -> list[dict]:
    with open(path, encoding="utf-8", errors="replace") as f:
        rows = [to_email(r) for r in csv.DictReader(f)]
    return _dedupe(rows)


def load_nazario(d: Path) -> list[dict]:
    return _load(d / "Nazario_5.csv", lambda r: {
        "from": "", "reply_to": "", "attachments": [],
        "subject": _mask(r.get("subject", "")), "body": _mask(r.get("body", ""))[:5000],
        "label": "PHISHING" if r.get("label") == "1" else "LEGIT"})


def load_trec(d: Path) -> list[dict]:
    return _load(d / "email_text.csv", lambda r: {
        "from": "", "reply_to": "", "attachments": [], "subject": "",
        "body": (r.get("text", "") or "")[:5000],
        "label": "SPAM" if r.get("label") == "1" else "LEGIT"})


def split(emails: list[dict], frac: float = 0.7) -> tuple[list[dict], list[dict]]:
    shuffled = emails[:]
    random.Random(SEED).shuffle(shuffled)  # noqa: S311  reproducible split, not security
    k = int(len(shuffled) * frac)
    return shuffled[:k], shuffled[k:]


def report(name: str, clf: EmailClassifier, test: list[dict]) -> None:
    yt = [e["label"] in MALICIOUS for e in test]
    yp = [v.label in MALICIOUS for v in clf.predict(test)]
    tp = sum(a and b for a, b in zip(yt, yp))
    fp = sum(b and not a for a, b in zip(yt, yp))
    fn = sum(a and not b for a, b in zip(yt, yp))
    tn = len(yt) - tp - fp - fn
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    far = fp / (fp + tn) if fp + tn else 0.0
    print(f"  {name:46} stopped {tp}/{tp + fn} ({100 * rec:4.1f}%)   "
          f"false alarms {fp}/{fp + tn} ({100 * far:4.1f}%)   F1 {f1:.3f}")


def fit(backend: str, data: list[dict]) -> EmailClassifier:
    return EmailClassifier(backend).fit(data, [e["label"] for e in data])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", default=None, help="folder with Nazario_5.csv and email_text.csv")
    ap.add_argument("--trec-sample", type=int, default=0,
                    help="use only N TREC emails (0 = all; try 4000 on the slow pure-Python backend)")
    args = ap.parse_args()

    d = Path(args.data_dir) if args.data_dir else _default_dir()
    if not (d / "Nazario_5.csv").is_file():
        print(f"Could not find Nazario_5.csv in {d}\n"
              f"Download the dataset and pass --data-dir (see the top of this file).")
        return 2

    backend = "sklearn" if sklearn_available() else "stdlib"
    print(f"backend: {backend}"
          + ("" if backend == "sklearn" else "   (install scikit-learn; stdlib is slow on the TREC set)"))

    nazario = load_nazario(d)
    trec = load_trec(d)
    if args.trec_sample and args.trec_sample < len(trec):
        trec = random.Random(SEED).sample(trec, args.trec_sample)  # noqa: S311  reproducible sample
    print(f"Nazario: {len(nazario)} emails   TREC: {len(trec)} emails   (duplicates removed)\n")

    nz_tr, nz_te = split(nazario)
    tr_tr, tr_te = split(trec)
    builtin = ev.load_corpus(None)

    print("BEFORE  (model as Aegis ships it: trained on 100 synthetic emails)")
    before = fit(backend, builtin)
    report("-> real phishing (Nazario)", before, nz_te)
    report("-> real spam (TREC)", before, tr_te)

    print("\nAFTER  (trained on synthetic + Nazario + TREC)")
    after = fit(backend, builtin + nz_tr + tr_tr)
    report("-> real phishing (Nazario)", after, nz_te)
    report("-> real spam (TREC)", after, tr_te)

    print("\nCROSS-SOURCE  (how well one source transfers to the other)")
    report("train TREC only  -> test Nazario", fit(backend, tr_tr), nz_te)
    report("train Nazario only -> test TREC", fit(backend, nz_tr), tr_te)

    print("\nAll numbers are on held-out emails the model never trained on.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
