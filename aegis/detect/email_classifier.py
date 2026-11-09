"""Email threat classifier: TF-IDF + logistic regression, with explanations.

Two interchangeable backends with the same interface:

- "stdlib": a small pure-Python TF-IDF + multinomial logistic regression
  (softmax, L2, full-batch gradient descent). Deterministic, no dependencies.
- "sklearn": scikit-learn's TfidfVectorizer + LogisticRegression. Used when
  scikit-learn is installed and backend="auto" or "sklearn".

Features come from `featurize()`: word unigrams and bigrams of the subject,
body and attachment names, with numbers and long hex ids collapsed to
placeholders. With `use_headers=True`, header-derived tokens are added
(SPF/DKIM/DMARC results, Reply-To mismatch, attachment extensions).

Also included:
- `red_flags()`: interpretable heuristic checks that mirror the red flags in
  the corpus answer key, so a verdict can be explained in human terms.
- `ClassifierDetector`: wraps a trained model as an Aegis `Detector`, so its
  probability can feed the gateway as a risk score. As with every detector,
  the score can only escalate a decision, never permit a denied action.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from itertools import pairwise
from typing import Any

from aegis.core.schemas import RiskReport

LABELS = ("LEGIT", "PHISHING", "SPAM")
MALICIOUS = frozenset({"PHISHING", "SPAM"})
RISKY_EXTENSIONS = frozenset({".xlsm", ".docm", ".iso", ".html", ".htm", ".exe", ".js", ".vbs", ".scr", ".lnk"})

# How many independent *text* red flags must fire before the hybrid overrides a
# "looks legit" model call. Two keeps precision at 1.00 on the corpus (single
# flags appear on genuine urgent/billing mail); it only fires on the clear ones.
RULE_ESCALATION_MIN_FLAGS = 2
# Digits that commonly stand in for letters in lookalike domains (paypa1, g00gle).
_HOMOGLYPH_DIGITS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"}

_TOKEN = re.compile(r"[a-z0-9]+(?:['.\-][a-z0-9]+)*")
_HEX = re.compile(r"^[0-9a-f]{10,}$")
_NUM = re.compile(r"^\d[\d,.]*$")


# ---------------------------------------------------------------- features

def _norm_token(tok: str) -> str:
    if _HEX.match(tok) and any(c.isdigit() for c in tok):
        return "<hex>"
    if _NUM.match(tok):
        return "<num>"
    return tok


def text_tokens(text: str) -> list[str]:
    words = [_norm_token(t) for t in _TOKEN.findall(text.lower())]
    return words + [f"{a} {b}" for a, b in pairwise(words)]


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def header_tokens(email: Mapping[str, Any]) -> list[str]:
    out = []
    auth = email.get("auth") or {}
    for k in ("spf", "dkim", "dmarc"):
        out.append(f"__auth_{k}_{auth.get(k, 'missing')}")
    if _domain(email.get("reply_to", "")) != _domain(email.get("from", "")):
        out.append("__replyto_mismatch")
    for name in email.get("attachments", []):
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        out.append(f"__att_ext{ext or '_none'}")
    return out


def featurize(email: Mapping[str, Any], use_headers: bool = False) -> list[str]:
    text = " ".join([email.get("subject", ""), email.get("body", ""), *email.get("attachments", [])])
    toks = text_tokens(text)
    return toks + header_tokens(email) if use_headers else toks


# ---------------------------------------------------------------- red flags

_RED_FLAG_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("urgency or threat", re.compile(r"within 24 hours|immediately|tonight|final notice|suspension|suspended|"
                                     r"blocked|frozen|legal action|loss of access|disconnection", re.I)),
    ("credential or PIN request", re.compile(r"verify (your )?(details|identity)|password to authori|upi pin|"
                                             r"card details|sign in with your email password", re.I)),
    ("macro / enable-content lure", re.compile(r"enable content|macros", re.I)),
    ("money or fee request", re.compile(r"processing fee|registration fee|small fee|pay a|wire|"
                                        r"bank details", re.I)),
    ("payment-detail change", re.compile(r"bank account has changed|new account|changed banks", re.I)),
    ("secrecy", re.compile(r"do not discuss|reply only to this email|discreet", re.I)),
    ("generic greeting", re.compile(r"^\s*dear (user|customer)\b", re.I | re.M)),
    ("too-good-to-be-true offer", re.compile(r"you have won|lottery|guaranteed|no cibil|no interview|"
                                             r"pre-approved|dormant funds|80% off", re.I)),
    ("phone callback", re.compile(r"\bcall \d", re.I)),
)


def lookalike_domain(addr: str) -> str | None:
    """Return the domain if its first label looks like a brand faked with
    digit-for-letter homoglyphs (paypa1, g00gle, amaz0n), else None.

    Conservative on purpose: the label must be mostly letters with at most two
    homoglyph digits, each sitting next to a letter, so legitimate domains that
    contain numbers (office365, 3m, s3) are not flagged."""
    dom = _domain(addr)
    if not dom:
        return None
    label = dom.split(".", 1)[0]
    letters = sum(c.isalpha() for c in label)
    digits = [c for c in label if c.isdigit()]
    if letters < 4 or not digits or len(digits) > 2:
        return None
    if any(c.isdigit() and c not in _HOMOGLYPH_DIGITS for c in label):
        return None  # a non-homoglyph digit (e.g. a year) -> probably real
    for i, c in enumerate(label):
        if c in _HOMOGLYPH_DIGITS:
            left = i > 0 and label[i - 1].isalpha()
            right = i < len(label) - 1 and label[i + 1].isalpha()
            if left or right:
                return dom
    return None


def text_red_flags(email: Mapping[str, Any]) -> list[str]:
    """Only the red flags that come from the email *text* (subject + body), with
    no header/authentication signal. These are what the hybrid classifier uses,
    so its lift does not depend on the corpus's authentication-header artifact."""
    text = email.get("subject", "") + "\n" + email.get("body", "")
    return [name for name, rx in _RED_FLAG_RULES if rx.search(text)]


def red_flags(email: Mapping[str, Any]) -> list[str]:
    """Human-readable red flags. Heuristic and written while viewing the corpus,
    so treat counts on that corpus as development measurements."""
    flags = []
    auth = email.get("auth") or {}
    # Only judge authentication when results are known (pasted text has none).
    if auth and (auth.get("spf") != "pass" or auth.get("dmarc") != "pass"):
        flags.append(f"authentication failed (SPF={auth.get('spf')}, DMARC={auth.get('dmarc')})")
    if _domain(email.get("reply_to", "")) != _domain(email.get("from", "")):
        flags.append("Reply-To domain differs from sender")
    look = lookalike_domain(email.get("from", ""))
    if look:
        flags.append(f"sender domain looks faked ({look})")
    for name in email.get("attachments", []):
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in RISKY_EXTENSIONS:
            flags.append(f"risky attachment type ({ext})")
    flags += text_red_flags(email)
    return flags


# ---------------------------------------------------------------- stdlib model

@dataclass
class _StdlibTfidfLogReg:
    l2: float = 1e-3
    lr: float = 2.0
    epochs: int = 400
    min_df: int = 1
    vocab: dict[str, int] = field(default_factory=dict)
    idf: list[float] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    W: list[list[float]] = field(default_factory=list)  # [class][feature]
    b: list[float] = field(default_factory=list)

    def _vector(self, toks: Sequence[str]) -> dict[int, float]:
        tf = Counter(t for t in toks if t in self.vocab)
        vec = {self.vocab[t]: c * self.idf[self.vocab[t]] for t, c in tf.items()}
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {i: v / norm for i, v in vec.items()}

    def fit(self, docs: Sequence[Sequence[str]], y: Sequence[str]) -> _StdlibTfidfLogReg:
        df = Counter(t for d in docs for t in set(d))
        terms = sorted(t for t, c in df.items() if c >= self.min_df)
        self.vocab = {t: i for i, t in enumerate(terms)}
        n = len(docs)
        self.idf = [math.log((1 + n) / (1 + df[t])) + 1.0 for t in terms]
        self.classes = sorted(set(y))
        k, m = len(self.classes), len(terms)
        X = [self._vector(d) for d in docs]
        Y = [self.classes.index(c) for c in y]
        self.W = [[0.0] * m for _ in range(k)]
        self.b = [0.0] * k
        for _ in range(self.epochs):
            gW = [[0.0] * m for _ in range(k)]
            gb = [0.0] * k
            for x, yi in zip(X, Y, strict=True):
                p = self._softmax(x)
                for c in range(k):
                    err = p[c] - (1.0 if c == yi else 0.0)
                    gb[c] += err
                    row = gW[c]
                    for j, v in x.items():
                        row[j] += err * v
            for c in range(k):
                Wc, gWc = self.W[c], gW[c]
                for j in range(m):
                    Wc[j] -= self.lr * (gWc[j] / n + self.l2 * Wc[j])
                self.b[c] -= self.lr * gb[c] / n
        return self

    def _softmax(self, x: Mapping[int, float]) -> list[float]:
        z = [self.b[c] + sum(self.W[c][j] * v for j, v in x.items()) for c in range(len(self.classes))]
        mx = max(z)
        e = [math.exp(v - mx) for v in z]
        s = sum(e)
        return [v / s for v in e]

    def predict_proba(self, docs: Sequence[Sequence[str]]) -> list[dict[str, float]]:
        return [dict(zip(self.classes, self._softmax(self._vector(d)), strict=True)) for d in docs]

    def top_features(self, toks: Sequence[str], label: str, k: int = 5) -> list[tuple[str, float]]:
        x = self._vector(toks)
        c = self.classes.index(label)
        inv = {i: t for t, i in self.vocab.items()}
        contrib = sorted(((inv[j], self.W[c][j] * v) for j, v in x.items()), key=lambda kv: -kv[1])
        return [(t, round(w, 4)) for t, w in contrib[:k] if w > 0]


# ---------------------------------------------------------------- sklearn model

class _SklearnTfidfLogReg:
    def __init__(self, C: float = 10.0) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression

        self.vec = TfidfVectorizer(analyzer=lambda toks: toks, lowercase=False, sublinear_tf=False)
        self.clf = LogisticRegression(C=C, max_iter=2000)
        self.classes: list[str] = []

    def fit(self, docs: Sequence[Sequence[str]], y: Sequence[str]) -> _SklearnTfidfLogReg:
        X = self.vec.fit_transform(list(docs))
        self.clf.fit(X, list(y))
        self.classes = [str(c) for c in self.clf.classes_]
        return self

    def predict_proba(self, docs: Sequence[Sequence[str]]) -> list[dict[str, float]]:
        P = self.clf.predict_proba(self.vec.transform(list(docs)))
        return [dict(zip(self.classes, map(float, row), strict=True)) for row in P]

    def top_features(self, toks: Sequence[str], label: str, k: int = 5) -> list[tuple[str, float]]:
        x = self.vec.transform([list(toks)]).tocoo()
        names = self.vec.get_feature_names_out()
        coef = self.clf.coef_
        if len(self.classes) == 2:  # binary sklearn stores one row for classes_[1]
            row = coef[0] if label == self.classes[1] else -coef[0]
        else:
            row = coef[self.classes.index(label)]
        contrib = sorted(((str(names[j]), float(row[j] * v)) for j, v in zip(x.col, x.data, strict=True)),
                         key=lambda kv: -kv[1])
        return [(t, round(w, 4)) for t, w in contrib[:k] if w > 0]


def sklearn_available() -> bool:
    try:
        import sklearn  # noqa: F401
    except ImportError:
        return False
    return True


# ---------------------------------------------------------------- public API

@dataclass(frozen=True)
class Verdict:
    label: str
    probabilities: dict[str, float]
    malicious_probability: float
    top_features: list[tuple[str, float]]
    red_flags: list[str]

    def explain(self) -> str:
        feats = ", ".join(t for t, _ in self.top_features) or "none"
        flags = "; ".join(self.red_flags) or "none"
        return (f"{self.label} (P(malicious)={self.malicious_probability:.2f}). "
                f"Strongest words: {feats}. Red flags: {flags}.")


class EmailClassifier:
    def __init__(self, backend: str = "auto", use_headers: bool = False, use_rules: bool = False) -> None:
        if backend not in ("auto", "stdlib", "sklearn"):
            raise ValueError("backend must be auto, stdlib or sklearn")
        if backend == "sklearn" and not sklearn_available():
            raise ImportError("scikit-learn is not installed: pip install scikit-learn")
        self.backend = "sklearn" if backend == "sklearn" or (backend == "auto" and sklearn_available()) \
            else "stdlib"
        self.use_headers = use_headers
        self.use_rules = use_rules
        self._model: _StdlibTfidfLogReg | _SklearnTfidfLogReg | None = None

    @property
    def name(self) -> str:
        return (f"email-tfidf-logreg-{self.backend}"
                f"{'+headers' if self.use_headers else ''}{'+rules' if self.use_rules else ''}")

    def fit(self, emails: Sequence[Mapping[str, Any]], labels: Sequence[str]) -> EmailClassifier:
        if len(emails) != len(labels) or not emails:
            raise ValueError("emails and labels must be non-empty and the same length")
        docs = [featurize(e, self.use_headers) for e in emails]
        self._model = _SklearnTfidfLogReg() if self.backend == "sklearn" else _StdlibTfidfLogReg()
        self._model.fit(docs, labels)
        return self

    def _require(self) -> _StdlibTfidfLogReg | _SklearnTfidfLogReg:
        if self._model is None:
            raise RuntimeError("classifier is not trained; call fit() first")
        return self._model

    def predict(self, emails: Sequence[Mapping[str, Any]]) -> list[Verdict]:
        model = self._require()
        docs = [featurize(e, self.use_headers) for e in emails]
        out = []
        for e, toks, probs in zip(emails, docs, model.predict_proba(docs), strict=True):
            label = max(probs, key=lambda c: probs[c])
            p_mal = sum(v for c, v in probs.items() if c in MALICIOUS)
            flags = red_flags(e)
            # Hybrid: if the model says "legit" but several independent text red
            # flags fire, trust the rules. Catches template families the model
            # never trained on without touching its false-positive rate.
            if self.use_rules and label == "LEGIT" and len(text_red_flags(e)) >= RULE_ESCALATION_MIN_FLAGS:
                label = "PHISHING"
                p_mal = max(p_mal, 0.75)
            out.append(Verdict(label, {c: round(v, 4) for c, v in probs.items()}, round(p_mal, 4),
                               model.top_features(toks, label), flags))
        return out


class ClassifierDetector:
    """Adapter: a trained EmailClassifier as an Aegis Detector over raw text.

    Aegis detectors receive untrusted text only (no headers), so this uses the
    body-text features. The returned score is P(malicious)."""

    def __init__(self, clf: EmailClassifier) -> None:
        if clf.use_headers:
            raise ValueError("ClassifierDetector needs a text-only classifier (use_headers=False)")
        self.clf = clf
        self.name = clf.name

    def analyze(self, text: str) -> RiskReport:
        v = self.clf.predict([{"subject": "", "body": text, "attachments": []}])[0]
        cats = () if v.label == "LEGIT" else (v.label.lower(),)
        return RiskReport(score=min(1.0, max(0.0, v.malicious_probability)), categories=cats,
                          evidence=tuple(t for t, _ in v.top_features), detector=self.name)
