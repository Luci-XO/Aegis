"""Fails if the policy, policy engine or detector changed after the freeze.

The held-out split was written after these hashes were recorded. Changing any
frozen file means held-out results are no longer clean; update
aegis/eval/freeze.json deliberately and label later results as post-hoc.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_frozen_components_unchanged():
    freeze = json.loads((ROOT / "aegis" / "eval" / "freeze.json").read_text("utf-8"))
    for rel, expected in freeze["sha256"].items():
        actual = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
        assert actual == expected, f"{rel} changed after the freeze ({freeze['frozen_at']})"
