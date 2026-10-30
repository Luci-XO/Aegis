"""Detector interface and a fail-safe wrapper.

`SafeDetector` turns every detector failure (exception, timeout, wrong return
type) into `None`, meaning "no result". The policy engine treats `None` as
grounds to escalate side effects (rule P012), so a broken or slow detector can
make the system stricter but never more permissive.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Protocol

from aegis.core.schemas import RiskReport

log = logging.getLogger("aegis.detect")

MAX_INPUT_CHARS = 20_000


class Detector(Protocol):
    name: str

    def analyze(self, text: str) -> RiskReport: ...


class SafeDetector:
    def __init__(self, inner: Detector, timeout_s: float = 2.0) -> None:
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        self.inner = inner
        self.name = getattr(inner, "name", "unknown")
        self.timeout_s = timeout_s
        self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="aegis-detector")

    def analyze(self, text: str) -> RiskReport | None:
        if not isinstance(text, str):
            return None
        future = self._pool.submit(self.inner.analyze, text[:MAX_INPUT_CHARS])
        try:
            report = future.result(timeout=self.timeout_s)
        except FutureTimeout:
            log.warning("detector %s timed out", self.name)
            return None
        except Exception:  # broad on purpose: a failing detector yields no result
            log.warning("detector %s raised", self.name, exc_info=True)
            return None
        if not isinstance(report, RiskReport):
            log.warning("detector %s returned %s", self.name, type(report).__name__)
            return None
        return report


def combine(reports: list[RiskReport | None]) -> RiskReport | None:
    """Aggregate per-document reports for a session.

    Any missing result makes the whole aggregate unknown (None). Otherwise the
    score is the maximum, and categories and evidence are merged.
    """
    if any(r is None for r in reports):
        return None
    real = [r for r in reports if r is not None]
    if not real:
        return RiskReport(score=0.0, detector="no-untrusted-input")
    top = max(real, key=lambda r: r.score)
    cats = tuple(sorted({c for r in real for c in r.categories}))
    ev = tuple(dict.fromkeys(e for r in real for e in r.evidence))
    return RiskReport(score=top.score, categories=cats, evidence=ev, detector=top.detector)
