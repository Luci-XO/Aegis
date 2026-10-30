"""Core data types shared by the policy engine, gateway and tools."""

from __future__ import annotations

import enum
import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from aegis.core.canonical import action_hash as _action_hash

ArgValue = str | tuple[str, ...]


class Sensitivity(enum.IntEnum):
    """Data classification. Higher value means more sensitive."""

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2

    @classmethod
    def parse(cls, value: str) -> Sensitivity:
        try:
            return cls[value.upper()]
        except (KeyError, AttributeError):
            raise ValueError(f"unknown sensitivity: {value!r}") from None


class Effect(str, enum.Enum):
    READ_ONLY = "read_only"
    LOCAL_WRITE = "local_write"  # changes sandbox state, nothing leaves it (e.g. drafts)
    EXTERNAL_SIDE_EFFECT = "external_side_effect"  # data leaves the system (e.g. send)


class Verdict(enum.IntEnum):
    """Ordered by severity so the strictest verdict wins with max()."""

    ALLOW = 0
    REQUIRE_APPROVAL = 1
    DENY = 2

    @classmethod
    def parse(cls, value: str) -> Verdict:
        try:
            return cls[value.upper()]
        except (KeyError, AttributeError):
            raise ValueError(f"unknown verdict: {value!r}") from None


@dataclass(frozen=True)
class Reason:
    rule_id: str
    verdict: Verdict
    message: str


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reasons: tuple[Reason, ...]
    action_hash: str | None

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(r.rule_id for r in self.reasons)

    @staticmethod
    def from_reasons(reasons: list[Reason], action_hash: str | None) -> Decision:
        verdict = max((r.verdict for r in reasons), default=Verdict.ALLOW)
        return Decision(verdict=verdict, reasons=tuple(reasons), action_hash=action_hash)


@dataclass(frozen=True)
class TaskGrant:
    """Capabilities derived from the trusted user task.

    Untrusted content can never widen a grant. In the MVP, grants come from
    task templates the user selects.
    """

    task_id: str
    allowed_tools: frozenset[str]
    allowed_email_ids: frozenset[str] = frozenset()
    allowed_file_ids: frozenset[str] = frozenset()
    allowed_recipients: frozenset[str] = frozenset()
    max_read_sensitivity: Sensitivity = Sensitivity.INTERNAL
    expires_at: float | None = None

    def __post_init__(self) -> None:
        for name in ("allowed_tools", "allowed_email_ids", "allowed_file_ids", "allowed_recipients"):
            value = getattr(self, name)
            if not isinstance(value, frozenset) or not all(isinstance(v, str) for v in value):
                raise TypeError(f"TaskGrant.{name} must be a frozenset of str")
        if any(r != r.lower() for r in self.allowed_recipients):
            raise ValueError("TaskGrant.allowed_recipients must be lower-case")
        if not isinstance(self.max_read_sensitivity, Sensitivity):
            raise TypeError("TaskGrant.max_read_sensitivity must be a Sensitivity")


@dataclass(frozen=True)
class RiskReport:
    """Output of a threat detector. Evidence only, never an authorization."""

    score: float
    categories: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    detector: str = "unknown"

    def __post_init__(self) -> None:
        if isinstance(self.score, bool) or not isinstance(self.score, (int, float)):
            raise TypeError("risk score must be a number")
        if math.isnan(self.score) or not 0.0 <= self.score <= 1.0:
            raise ValueError("risk score must be within [0, 1]")


@dataclass(frozen=True, eq=False)
class ValidatedCall:
    """A tool call that passed schema validation.

    Arguments are normalised and immutable. The gateway passes this exact
    object to the tool, so the checked values are the executed values.
    """

    session_id: str
    tool: str
    args: Mapping[str, ArgValue]
    action_hash: str

    @staticmethod
    def create(session_id: str, tool: str, args: Mapping[str, ArgValue]) -> ValidatedCall:
        frozen = MappingProxyType(dict(args))
        return ValidatedCall(
            session_id=session_id,
            tool=tool,
            args=frozen,
            action_hash=_action_hash(session_id, tool, frozen),
        )

    def plain_args(self) -> dict[str, str | list[str]]:
        return {k: list(v) if isinstance(v, tuple) else v for k, v in self.args.items()}
