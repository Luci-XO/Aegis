"""Fails if the policy, policy engine or detector changed after the freeze.

The held-out split was written after these hashes were recorded. Changing any
frozen file means held-out results are no longer clean; update
aegis/eval/freeze.json deliberately and label later results as post-hoc.

Hashes ignore line-ending style (LF vs CRLF), so a Windows checkout with
core.autocrlf=true passes, while any real content change still fails.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegis.eval.benchmark import text_sha256

ROOT = Path(__file__).resolve().parents[1]
FREEZE = json.loads((ROOT / "aegis" / "eval" / "freeze.json").read_text("utf-8"))


def test_frozen_components_unchanged():
    for rel, expected in FREEZE["sha256"].items():
        assert text_sha256(ROOT / rel) == expected, f"{rel} changed after the freeze ({FREEZE['frozen_at']})"


def test_hash_ignores_crlf_but_catches_content_changes(tmp_path):
    original = (ROOT / "aegis" / "policies" / "default.json").read_bytes().replace(b"\r\n", b"\n")
    expected = FREEZE["sha256"]["aegis/policies/default.json"]
    windows = tmp_path / "crlf.json"
    windows.write_bytes(original.replace(b"\n", b"\r\n"))
    assert text_sha256(windows) == expected
    edited = tmp_path / "edited.json"
    edited.write_bytes(original.replace(b'"escalation_threshold": 0.5', b'"escalation_threshold": 0.9'))
    assert text_sha256(edited) != expected
