"""Agent interface.

An agent proposes one step at a time: either a tool request (an untrusted
object the gateway will validate) or a final message. After each request it
is told the gateway's answer (`GatewayResult.for_agent()`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from aegis.agent.tasks import TaskInstance


@dataclass(frozen=True)
class AgentStep:
    request: object | None = None  # tool request, deliberately untyped: it is untrusted
    final: str | None = None

    @property
    def is_final(self) -> bool:
        return self.request is None


class Agent(Protocol):
    name: str

    def start(self, task: TaskInstance) -> None: ...

    def next_step(self) -> AgentStep: ...

    def observe(self, request: object, result: dict[str, Any]) -> None: ...

    def metadata(self) -> dict[str, Any]: ...
