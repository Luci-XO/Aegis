"""Per-session security state maintained by the gateway.

The session label is a "high-water mark": the highest sensitivity of any data
the gateway has actually returned to the agent in this session. Once the agent
has seen confidential data, every later outgoing message is treated as
potentially containing it, regardless of how the agent rewords it. This is
coarse but holds up against paraphrasing and encoding tricks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.core.schemas import Sensitivity, TaskGrant, ValidatedCall

_SESSION_ID = re.compile(r"[A-Za-z0-9_-]{1,64}", re.ASCII)


@dataclass(frozen=True)
class ExecutedAction:
    tool: str
    action_hash: str
    approval_request_id: str | None
    at: float


class SessionState:
    def __init__(self, session_id: str, grant: TaskGrant) -> None:
        if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id):
            raise ValueError("session_id must match [A-Za-z0-9_-]{1,64}")
        if not isinstance(grant, TaskGrant):
            raise TypeError("grant must be a TaskGrant")
        self.session_id = session_id
        self.grant = grant
        self._label = Sensitivity.PUBLIC
        self._executed: list[ExecutedAction] = []

    @property
    def label(self) -> Sensitivity:
        return self._label

    @property
    def executed(self) -> tuple[ExecutedAction, ...]:
        return tuple(self._executed)

    def _record_execution(
        self,
        call: ValidatedCall,
        result_label: Sensitivity,
        approval_request_id: str | None,
        at: float,
    ) -> None:
        """Called only by the gateway after a tool has actually executed."""
        self._label = max(self._label, result_label)
        self._executed.append(
            ExecutedAction(call.tool, call.action_hash, approval_request_id, at)
        )
