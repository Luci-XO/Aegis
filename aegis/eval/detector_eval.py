"""Document-level detector evaluation.

Each unique document (email or file) belonging to a split is scored once.
Emails are scored on subject and body separately and the higher score is
used, matching what the runner does. A document is "flagged" if its score is
at or above the policy's escalation threshold.

Which documents belong to which split:
- dev:     the base synthetic emails and files plus documents added by dev cases
- heldout: only documents added by held-out cases
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from importlib import resources
from typing import Any

from aegis.agent.scenarios import Scenario
from aegis.detect.base import SafeDetector
from aegis.eval.metrics import DetectionCounts


def _base_docs() -> list[dict[str, Any]]:
    base = resources.files("aegis") / "data" / "synthetic"
    emails = json.loads((base / "emails.json").read_text("utf-8"))
    files = json.loads((base / "files.json").read_text("utf-8"))
    return [{"kind": "email", **e} for e in emails] + [{"kind": "file", **f} for f in files]


def documents_for(split: str, scenarios: Iterable[Scenario]) -> list[dict[str, Any]]:
    docs = _base_docs() if split == "dev" else []
    for sc in scenarios:
        docs += [{"kind": "email", **e} for e in sc.env_patch.get("emails", [])]
        docs += [{"kind": "file", **f} for f in sc.env_patch.get("files", [])]
    unique: dict[str, dict[str, Any]] = {}
    for d in docs:
        if "malicious" not in d:
            raise ValueError(f"document {d['id']} has no 'malicious' label")
        prev = unique.get(d["id"])
        if prev is not None and prev != d:
            raise ValueError(f"document id {d['id']} is defined twice with different content")
        unique[d["id"]] = d
    return [unique[k] for k in sorted(unique)]


def evaluate_detector(docs: list[dict[str, Any]], detector: SafeDetector, threshold: float) -> dict[str, Any]:
    tp = fp = fn = tn = failures = 0
    rows = []
    for d in docs:
        texts = [d.get("subject", ""), d.get("body", "")] if d["kind"] == "email" else [d.get("content", "")]
        reports = [detector.analyze(t) for t in texts if t]
        if any(r is None for r in reports):
            failures += 1
            score = None
        else:
            score = max((r.score for r in reports if r is not None), default=0.0)
        flagged = score is None or score >= threshold  # no result counts as flagged (fail closed)
        malicious = bool(d["malicious"])
        tp += malicious and flagged
        fp += (not malicious) and flagged
        fn += malicious and not flagged
        tn += (not malicious) and not flagged
        rows.append({"id": d["id"], "malicious": malicious, "score": score, "flagged": flagged})
    return {"threshold": threshold, "documents": len(docs), "detector_failures": failures,
            **DetectionCounts(tp, fp, fn, tn).as_dict(), "per_document": rows}
