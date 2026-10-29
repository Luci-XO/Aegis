"""Canonical serialisation and hashing.

Approvals and audit records are bound to hashes, so the same logical value must
always serialise to the same bytes: sorted keys, no whitespace, tuples as lists,
and NaN/Infinity rejected.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        _plain(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def action_hash(session_id: str, tool: str, args: Mapping[str, Any]) -> str:
    """Hash identifying one exact proposed action within one session."""
    return sha256_hex(
        canonical_json({"v": 1, "session_id": session_id, "tool": tool, "args": args})
    )
