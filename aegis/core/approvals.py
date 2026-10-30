"""Human approval bound to one exact action.

Flow:
1. The gateway calls `create()` for a REQUIRE_APPROVAL decision. The request
   stores the action hash (session + tool + canonical arguments).
2. A human, through the UI and never through an agent tool, calls `approve()`
   and receives a token: "<request_id>.<HMAC-SHA256(secret, binding)>".
3. The agent resubmits the action together with the token. The gateway
   re-evaluates policy first (an approval can never override DENY), then calls
   `redeem()`, which checks the signature, status, expiry, session and exact
   action hash, and marks the token used.

What the HMAC adds: approval state is held on the server, so the HMAC mainly
makes tokens unforgeable (an agent cannot guess a valid token from a request
ID) and lets tampering be detected if tokens travel through untrusted
channels. It does not protect against theft of the secret key.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import os
import secrets
import threading
import warnings
from dataclasses import dataclass, field
from typing import Any

from aegis.core.clock import Clock, SystemClock
from aegis.core.schemas import Decision, ValidatedCall

SECRET_ENV = "AEGIS_APPROVAL_SECRET"  # noqa: S105 - env var name, not a secret


def load_secret(env: dict[str, str] | None = None) -> bytes:
    """Read the HMAC key from AEGIS_APPROVAL_SECRET (hex, at least 32 bytes).

    If it is unset, an ephemeral random key is generated. That is safe (all
    tokens become invalid on restart) but tokens will not survive a restart.
    """
    source = os.environ if env is None else env
    raw = source.get(SECRET_ENV)
    if not raw:
        warnings.warn(f"{SECRET_ENV} not set; using an ephemeral approval key", stacklevel=2)
        return secrets.token_bytes(32)
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise ValueError(f"{SECRET_ENV} must be hex-encoded") from None
    if len(key) < 32:
        raise ValueError(f"{SECRET_ENV} must decode to at least 32 bytes")
    return key


class ApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    USED = "used"
    REVOKED = "revoked"  # a different action was submitted with this token


@dataclass
class ApprovalRequest:
    request_id: str
    session_id: str
    action_hash: str
    tool: str
    display: dict[str, Any]  # rendered from the validated call, not from agent prose
    rule_ids: tuple[str, ...]
    created_at: float
    expires_at: float
    status: ApprovalStatus = ApprovalStatus.PENDING
    history: list[tuple[float, str]] = field(default_factory=list)


@dataclass(frozen=True)
class RedeemResult:
    ok: bool
    request_id: str | None
    rule_id: str | None  # A00x on failure


class ApprovalError(RuntimeError):
    pass


class ApprovalService:
    def __init__(self, secret: bytes, clock: Clock | None = None, ttl_seconds: float = 300.0) -> None:
        if len(secret) < 32:
            raise ValueError("approval secret must be at least 32 bytes")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._secret = secret
        self._clock = clock or SystemClock()
        self._ttl = ttl_seconds
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()

    def _mac(self, req: ApprovalRequest) -> str:
        binding = f"v1|{req.request_id}|{req.session_id}|{req.action_hash}|{req.expires_at!r}"
        return hmac.new(self._secret, binding.encode(), hashlib.sha256).hexdigest()

    def create(self, call: ValidatedCall, decision: Decision) -> ApprovalRequest:
        now = self._clock.now()
        req = ApprovalRequest(
            request_id=secrets.token_hex(16),
            session_id=call.session_id,
            action_hash=call.action_hash,
            tool=call.tool,
            display={"tool": call.tool, "args": call.plain_args()},
            rule_ids=decision.rule_ids,
            created_at=now,
            expires_at=now + self._ttl,
        )
        req.history.append((now, "created"))
        with self._lock:
            self._requests[req.request_id] = req
        return req

    def get(self, request_id: str) -> ApprovalRequest | None:
        return self._requests.get(request_id)

    def pending(self, session_id: str | None = None) -> list[ApprovalRequest]:
        return [
            r for r in self._requests.values()
            if r.status is ApprovalStatus.PENDING and (session_id is None or r.session_id == session_id)
        ]

    def approve(self, request_id: str) -> str:
        """Human action. Returns the single-use token."""
        with self._lock:
            req = self._requests.get(request_id)
            now = self._clock.now()
            if req is None:
                raise ApprovalError("unknown approval request")
            if req.status is not ApprovalStatus.PENDING:
                raise ApprovalError(f"request is {req.status.value}")
            if now >= req.expires_at:
                raise ApprovalError("request expired")
            req.status = ApprovalStatus.APPROVED
            req.history.append((now, "approved"))
            return f"{req.request_id}.{self._mac(req)}"

    def reject(self, request_id: str) -> None:
        with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                raise ApprovalError("unknown approval request")
            if req.status in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED):
                req.status = ApprovalStatus.REJECTED
                req.history.append((self._clock.now(), "rejected"))

    def redeem(self, token: object, call: ValidatedCall) -> RedeemResult:
        if not isinstance(token, str) or token.count(".") != 1 or len(token) > 200:
            return RedeemResult(False, None, "A001")
        request_id, mac = token.split(".")
        with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                return RedeemResult(False, None, "A002")
            if not hmac.compare_digest(mac, self._mac(req)):
                return RedeemResult(False, request_id, "A003")
            now = self._clock.now()
            if req.status is ApprovalStatus.USED:
                return RedeemResult(False, request_id, "A005")
            if req.status is not ApprovalStatus.APPROVED:
                return RedeemResult(False, request_id, "A004")
            if now >= req.expires_at:
                return RedeemResult(False, request_id, "A006")
            if call.session_id != req.session_id:
                return RedeemResult(False, request_id, "A007")
            if not hmac.compare_digest(call.action_hash, req.action_hash):
                # Someone tried to swap parameters under an existing approval.
                req.status = ApprovalStatus.REVOKED
                req.history.append((now, "revoked: action mismatch"))
                return RedeemResult(False, request_id, "A008")
            req.status = ApprovalStatus.USED
            req.history.append((now, "used"))
            return RedeemResult(True, request_id, None)
