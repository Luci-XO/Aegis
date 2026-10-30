"""Hash-chained audit log stored in SQLite.

Each record stores record_hash = SHA-256(prev_hash || canonical_record).

Guarantees, stated precisely:
- `verify()` detects modification of any record, deletion or insertion in the
  middle of the chain, and reordering.
- It does NOT detect removal of the newest records (tail truncation) or
  replacement of the whole log, unless you compare against an anchor saved
  elsewhere: `head()` returns (seq, hash) and `verify(anchor=...)` checks it.
- It does not stop anyone with write access from rewriting the file. It only
  makes such edits detectable.

Records hold IDs, rule IDs, hashes and redacted summaries. They never hold
email bodies, file contents or full addresses.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis.core.canonical import canonical_json, sha256_hex

GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY,
    record TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL
)
"""


class AuditError(RuntimeError):
    pass


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    reason: str | None = None


def _hash(prev_hash: str, record_json: str) -> str:
    return sha256_hex(prev_hash + "|" + record_json)


class AuditLog:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.execute(_SCHEMA)
        self._lock = threading.Lock()

    def append(self, record: dict[str, Any]) -> tuple[int, str]:
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                row = self._conn.execute(
                    "SELECT seq, record_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS)
                body = canonical_json({**record, "seq": seq})
                rhash = _hash(prev, body)
                self._conn.execute(
                    "INSERT INTO audit_log (seq, record, prev_hash, record_hash) VALUES (?, ?, ?, ?)",
                    (seq, body, prev, rhash),
                )
                self._conn.execute("COMMIT")
                return seq, rhash
            except Exception as exc:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise AuditError("audit append failed") from exc

    def records(self, session_id: str | None = None) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT record FROM audit_log ORDER BY seq").fetchall()
        out = [json.loads(r[0]) for r in rows]
        return [r for r in out if session_id is None or r.get("session_id") == session_id]

    def head(self) -> tuple[int, str]:
        row = self._conn.execute(
            "SELECT seq, record_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (row[0], row[1]) if row else (0, GENESIS)

    def verify(self, anchor: tuple[int, str] | None = None) -> VerifyResult:
        rows = self._conn.execute(
            "SELECT seq, record, prev_hash, record_hash FROM audit_log ORDER BY seq"
        ).fetchall()
        prev, expected_seq = GENESIS, 1
        for seq, body, prev_hash, rhash in rows:
            if seq != expected_seq:
                return VerifyResult(False, expected_seq - 1, expected_seq, "gap in sequence (record deleted)")
            if prev_hash != prev:
                return VerifyResult(False, seq - 1, seq, "broken link to previous record")
            try:
                if json.loads(body).get("seq") != seq:
                    return VerifyResult(False, seq - 1, seq, "sequence number altered")
            except json.JSONDecodeError:
                return VerifyResult(False, seq - 1, seq, "record is not valid JSON")
            if _hash(prev_hash, body) != rhash:
                return VerifyResult(False, seq - 1, seq, "record contents altered")
            prev, expected_seq = rhash, seq + 1
        checked = expected_seq - 1
        if anchor is not None:
            a_seq, a_hash = anchor
            if a_seq > checked:
                return VerifyResult(False, checked, checked + 1, "log is shorter than the saved anchor (truncated)")
            if a_seq > 0 and rows[a_seq - 1][3] != a_hash:
                return VerifyResult(False, checked, a_seq, "anchor hash mismatch")
        return VerifyResult(True, checked)

    def close(self) -> None:
        self._conn.close()
