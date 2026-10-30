"""Run loop: agent ⇄ gateway, with detector and approval handling.

For each step:
1. Ask the agent for its next step.
2. Submit the request to the gateway with the session's aggregated risk report.
3. If approval is required, ask the approver. Only the runner holds tokens;
   the agent never sees them. The runner resubmits the identical request.
4. If the tool executed and returned untrusted text, run the detector on it
   and add the result to the session's risk.
5. Give the agent the gateway's answer.

The user-facing report is built from the gateway's records, not from the
agent's final message, so a blocked action can never be reported as done.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from aegis.agent.approvers import Approver
from aegis.agent.base import Agent
from aegis.agent.tasks import TaskInstance
from aegis.core.gateway import Gateway, GatewayResult, Status
from aegis.core.schemas import RiskReport
from aegis.core.session import SessionState
from aegis.detect.base import SafeDetector, combine

log = logging.getLogger("aegis.runner")


@dataclass(frozen=True)
class StepRecord:
    index: int
    tool: str | None
    status: str
    rule_ids: tuple[str, ...]
    approval: str | None  # None | "approved" | "rejected"
    risk_score: float | None
    gateway_ms: float


@dataclass
class RunResult:
    case_id: str | None
    session_id: str
    task: str
    agent: dict[str, Any]
    approver: str
    detector: str | None
    steps: list[StepRecord] = field(default_factory=list)
    agent_claim: str | None = None
    stop_reason: str = "unknown"
    detections: list[dict[str, Any]] = field(default_factory=list)
    wall_ms: float = 0.0

    @property
    def executed_tools(self) -> list[str]:
        return [s.tool or "?" for s in self.steps if s.status == Status.EXECUTED.value]

    def report(self) -> str:
        """User-facing summary built only from gateway outcomes."""
        lines = [f"Task: {self.task}  (stopped: {self.stop_reason})"]
        for s in self.steps:
            extra = f" [{', '.join(s.rule_ids)}]" if s.rule_ids and s.status != "executed" else ""
            appr = f" approval={s.approval}" if s.approval else ""
            lines.append(f"  {s.index:>2}. {s.tool or '<invalid>'}: {s.status}{appr}{extra}")
        lines.append(f"Agent's own claim (unverified): {self.agent_claim!r}")
        return "\n".join(lines)


def _untrusted_texts(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        if value.get("trust") == "untrusted" and isinstance(value.get("text"), str):
            yield value["text"]
            return
        for v in value.values():
            yield from _untrusted_texts(v)
    elif isinstance(value, list):
        for v in value:
            yield from _untrusted_texts(v)


class Runner:
    def __init__(
        self,
        gateway: Gateway,
        approver: Approver,
        detector: SafeDetector | None,
        max_steps: int = 25,
    ) -> None:
        self.gateway = gateway
        self.approver = approver
        self.detector = detector
        self.max_steps = max_steps

    def _risk(self, reports: list[RiskReport | None]) -> RiskReport | None:
        if self.detector is None:
            return None
        return combine(reports)

    def run(self, agent: Agent, task: TaskInstance, session_id: str, case_id: str | None = None) -> RunResult:
        t0 = time.perf_counter()
        session = SessionState(session_id, task.grant)
        result = RunResult(
            case_id=case_id, session_id=session_id, task=task.template, agent=agent.metadata(),
            approver=self.approver.name, detector=self.detector.name if self.detector else None,
        )
        reports: list[RiskReport | None] = []
        try:
            agent.start(task)
        except Exception:  # broad on purpose: a broken agent executes nothing
            log.warning("agent failed to start", exc_info=True)
            result.stop_reason = "agent_error"
            return result

        for i in range(1, self.max_steps + 1):
            try:
                step = agent.next_step()
            except Exception:  # broad on purpose: stop, nothing is executed
                log.warning("agent raised", exc_info=True)
                result.stop_reason = "agent_error"
                break
            if step.is_final:
                result.agent_claim = step.final
                result.stop_reason = "final"
                break

            risk = self._risk(reports)
            gw = self.gateway.submit(step.request, session, risk=risk, case_id=case_id)
            gateway_ms = gw.latency_ms
            approval: str | None = None
            request_id = gw.approval_request_id
            if gw.status is Status.PENDING_APPROVAL and request_id:
                req = self.gateway.approvals.get(request_id)
                if req is not None and self.approver.decide(req, task):
                    approval = "approved"
                    token = self.gateway.approvals.approve(req.request_id)
                    gw = self.gateway.submit(step.request, session, risk=risk,
                                             approval_token=token, case_id=case_id)
                    gateway_ms += gw.latency_ms
                else:
                    approval = "rejected"
                    self.gateway.approvals.reject(request_id)

            if gw.executed and gw.output is not None and self.detector is not None:
                for text in _untrusted_texts(gw.output):
                    rep = self.detector.analyze(text)
                    reports.append(rep)
                    result.detections.append({
                        "step": i, "tool": gw.tool,
                        "score": None if rep is None else rep.score,
                        "evidence": [] if rep is None else list(rep.evidence),
                    })

            result.steps.append(StepRecord(
                index=i, tool=gw.tool, status=self._status(gw, approval), rule_ids=gw.rule_ids,
                approval=approval, risk_score=None if risk is None else risk.score, gateway_ms=gateway_ms,
            ))
            agent_view = gw.for_agent()
            if approval == "rejected":
                agent_view = {**agent_view, "status": "rejected_by_user"}
            try:
                agent.observe(step.request, agent_view)
            except Exception:  # broad on purpose
                log.warning("agent.observe raised", exc_info=True)
                result.stop_reason = "agent_error"
                break
        else:
            result.stop_reason = "max_steps"

        result.wall_ms = (time.perf_counter() - t0) * 1000
        return result

    @staticmethod
    def _status(gw: GatewayResult, approval: str | None) -> str:
        if approval == "rejected":
            return "rejected_by_user"
        return gw.status.value
