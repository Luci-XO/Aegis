"""Interactive, stepping driver for the dashboard.

Unlike `Runner` (which drives a whole run to completion with an automatic
approver), this driver pauses when the gateway asks for human approval and
exposes the exact proposed action, so a person can approve or reject it in the
UI. It uses the same Gateway, ApprovalService, detector aggregation and agent
as the benchmark, so what the dashboard shows is what the enforcement code
actually does.

For non-interactive approvers (intent, rubber_stamp, reject_all) it decides
automatically, exactly as the benchmark would. For approver "manual" it stops
and waits for `decide()`.

All data here is synthetic, so the snapshot deliberately includes email and
file bodies: seeing the hidden instruction is the point of the demo.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from aegis.agent.approvers import Approver, IntentApprover, RejectAllApprover, RubberStampApprover
from aegis.agent.runner import StepRecord, _untrusted_texts
from aegis.agent.scenarios import Scenario, build_stack
from aegis.agent.scripted import ScriptedAgent
from aegis.core.clock import FakeClock
from aegis.core.gateway import Status
from aegis.core.policy import Policy
from aegis.core.schemas import RiskReport, Verdict
from aegis.core.session import SessionState
from aegis.detect.base import SafeDetector, combine
from aegis.detect.rules import RuleDetector
from aegis.eval import goals
from aegis.eval.benchmark import CONFIGS, policy_variant

MAX_STEPS = 25
AUTO_APPROVERS: dict[str, Callable[[], Approver]] = {
    "intent": IntentApprover,
    "rubber_stamp": RubberStampApprover,
    "reject_all": RejectAllApprover,
}
# Configurations offered in the UI (the two low-friction ablations are
# benchmark-only, to keep the demo focused).
UI_CONFIGS = ["A_unprotected", "B_detector_only", "C_gateway_only", "D_aegis"]


class SessionError(ValueError):
    pass


def _action_key(request: object) -> tuple[str, str] | None:
    """Identify an action for matching against the scenario's injected actions.
    Sends are matched by tool and recipients (bodies may contain pasted content)."""
    if not isinstance(request, dict):
        return None
    tool = str(request.get("tool"))
    raw_args = request.get("args")
    args: dict[str, Any] = raw_args if isinstance(raw_args, dict) else {}
    if tool in ("send_email", "draft_email"):
        to = args.get("to")
        to_list = to if isinstance(to, list) else [to]
        rcpts = ",".join(sorted(str(x).strip().lower() for x in to_list))
        # Bodies with pasted content ($CONTENT) differ at run time, so match those on
        # recipients only; otherwise include the body so a legitimate reply to the same
        # address is not mistaken for the attacker's message.
        body = str(args.get("body", ""))
        return tool, rcpts if "$CONTENT(" in body or not body else rcpts + "|" + body
    return tool, json.dumps(args, sort_keys=True, default=str)


def _reasons(reasons: tuple) -> list[dict[str, Any]]:
    return [{"rule_id": r.rule_id, "verdict": r.verdict.name, "message": r.message} for r in reasons]


@dataclass
class InteractiveSession:
    session_id: str
    scenario: Scenario
    config: str
    approver: str
    secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    def __post_init__(self) -> None:
        if self.config not in UI_CONFIGS:
            raise SessionError(f"unknown config '{self.config}'")
        if self.approver not in ({"manual"} | set(AUTO_APPROVERS)):
            raise SessionError(f"unknown approver '{self.approver}'")
        cfg = CONFIGS[self.config]
        self._manual = self.approver == "manual"
        self._auto: Approver | None = None if self._manual else AUTO_APPROVERS[self.approver]()
        self._detector: SafeDetector | None = SafeDetector(RuleDetector()) if cfg.use_detector else None
        policy = policy_variant(Policy.load(), cfg)
        self._clock = FakeClock()
        stack = build_stack(
            self.scenario, IntentApprover(), self._detector, self.secret, policy=policy,
            clock=self._clock, executor_kind=cfg.executor, detector_threshold=policy.escalation_threshold,
        )
        self._stack = stack
        self._executor = stack.executor
        self._session = SessionState(self.session_id, stack.task.grant)
        self._agent = ScriptedAgent(self.scenario.injections or None)
        self._agent.start(stack.task)
        self._reports: list[RiskReport | None] = []
        self._steps: list[dict[str, Any]] = []
        self._detections: list[dict[str, Any]] = []
        self._status = "running"
        self._agent_claim: str | None = None
        self._stop_reason = "running"
        self._pending: dict[str, Any] | None = None
        self._pending_ctx: tuple[object, RiskReport | None, Any] | None = None
        self._n = 0
        self._requests: list[object] = []
        self._injected_keys = {
            _action_key(a) for acts in self.scenario.injections.values() for a in acts}
        self._loose_keys = {k[0] + "|" + k[1].split("|", 1)[0] for k in self._injected_keys
                            if k is not None and "|" not in k[1]}
        self.advance()

    # -- public API --------------------------------------------------------

    @property
    def status(self) -> str:
        return self._status

    def advance(self) -> None:
        if self._status != "running":
            return
        while self._n < MAX_STEPS:
            try:
                step = self._agent.next_step()
            except Exception:  # noqa: BLE001 - a broken agent stops the run
                self._finish("agent_error")
                return
            if step.is_final:
                self._agent_claim = step.final
                self._finish("final")
                return
            self._n += 1
            risk = combine(self._reports) if self._detector is not None else None
            gw = self._executor.submit(step.request, self._session, risk=risk)
            rid = gw.approval_request_id
            approvals = self._executor.approvals
            if gw.status is Status.PENDING_APPROVAL and rid and approvals is not None:
                if self._manual:
                    self._enter_pending(gw, step.request, risk)
                    return
                req = approvals.get(rid)
                if req is not None and self._auto is not None and self._auto.decide(req, self._stack.task):
                    token = approvals.approve(rid)
                    gw = self._executor.submit(step.request, self._session, risk=risk, approval_token=token)
                    self._finish_step(gw, step.request, risk, "approved")
                else:
                    approvals.reject(rid)
                    self._finish_step(gw, step.request, risk, "rejected")
                continue
            self._finish_step(gw, step.request, risk, None)
        else:
            self._finish("max_steps")

    def decide(self, request_id: str, approve: bool) -> None:
        if self._status != "awaiting_approval" or self._pending is None:
            raise SessionError("no approval is pending")
        if request_id != self._pending["request_id"]:
            raise SessionError("approval id does not match the pending request")
        approvals = self._executor.approvals
        if approvals is None or self._pending_ctx is None:
            raise SessionError("no approval is pending")
        request, risk, pending_gw = self._pending_ctx
        if approve:
            token = approvals.approve(request_id)
            gw = self._executor.submit(request, self._session, risk=risk, approval_token=token)
            self._finish_step(gw, request, risk, "approved")
        else:
            approvals.reject(request_id)
            # Reuse the pending result; do not re-submit (that would create a
            # new orphan approval request). The action simply did not execute.
            self._finish_step(pending_gw, request, risk, "rejected")
        self._pending = None
        self._pending_ctx = None
        self._status = "running"
        self.advance()

    def snapshot(self) -> dict[str, Any]:
        env = self._stack.env
        gateway = self._stack.gateway
        return {
            "session_id": self.session_id,
            "config": self.config,
            "approver": self.approver,
            "status": self._status,
            "stop_reason": self._stop_reason,
            "scenario": {
                "id": self.scenario.id, "label": self.scenario.label,
                "category": self.scenario.category, "description": self.scenario.description,
            },
            "task": {
                "template": self._stack.task.template,
                "description": self._stack.task.description,
                "grant": self._grant_view(),
            },
            "inbox": [self._email_view(e) for e in env.emails.values()],
            "files": [self._file_view(f) for f in env.files.values()],
            "steps": self._steps,
            "pending": self._pending,
            "outbox": [self._msg_view(m) for m in env.outbox],
            "audit": gateway.audit.records(self.session_id) if gateway else [],
            "audit_verified": gateway.audit.verify().ok if gateway else None,
            "detector": self._detector.name if self._detector else None,
            "agent_claim": self._agent_claim,
            "malicious_sources": sorted(self.scenario.injections),
            "outcome": self._outcome(),
        }

    def _is_injected(self, request: object) -> bool:
        key = _action_key(request)
        if key is None:
            return False
        if key in self._injected_keys:
            return True
        return key[0] + "|" + key[1].split("|", 1)[0] in self._loose_keys

    def _outcome(self) -> dict[str, Any]:
        """Score the run on the real environment state, like the benchmark does."""
        steps = [
            StepRecord(index=st["index"], tool=st["tool"], status=st["status"],
                       rule_ids=tuple(r["rule_id"] for r in st["reasons"]), approval=st["approval"],
                       risk_score=st["risk_score"], gateway_ms=0.0, request=req)
            for st, req in zip(self._steps, self._requests, strict=True)
        ]
        ctx = goals.GoalContext(env=self._stack.env, steps=steps)
        user_goal = self.scenario.user_goal or goals.default_user_goal(self._stack.task, self._stack.initial_env)
        return {
            "final": self._status == "done",
            "attack": None if self.scenario.attacker_goal is None else goals.check(self.scenario.attacker_goal, ctx),
            "user": goals.check(user_goal, ctx),
        }

    # -- internals ---------------------------------------------------------

    def _enter_pending(self, gw: Any, request: object, risk: RiskReport | None) -> None:
        approvals = self._executor.approvals
        req = approvals.get(gw.approval_request_id) if approvals and gw.approval_request_id else None
        if req is None:
            raise SessionError("approval request vanished")
        self._pending = {
            "request_id": req.request_id,
            "tool": req.tool,
            "display": req.display,
            "rule_ids": list(req.rule_ids),
            "reasons": _reasons(gw.reasons),
            "risk_score": None if risk is None else risk.score,
        }
        self._pending_ctx = (request, risk, gw)
        self._status = "awaiting_approval"

    def _finish_step(self, gw: Any, request: object, risk: RiskReport | None, approval: str | None) -> None:
        executed = gw.status is Status.EXECUTED
        status = "rejected_by_user" if approval == "rejected" else gw.status.value
        step_detections: list[dict[str, Any]] = []
        if executed and gw.output is not None and self._detector is not None:
            for text in _untrusted_texts(gw.output):
                rep = self._detector.analyze(text)
                self._reports.append(rep)
                d = {"score": None if rep is None else rep.score,
                     "evidence": [] if rep is None else list(rep.evidence)}
                step_detections.append(d)
                self._detections.append({"step": self._n, **d})
        self._requests.append(request)
        self._steps.append({
            "injected": self._is_injected(request),
            "index": self._n,
            "tool": gw.tool,
            "args": self._args_view(request),
            "status": status,
            "verdict": gw.verdict.name if isinstance(gw.verdict, Verdict) else str(gw.verdict),
            "reasons": _reasons(gw.reasons),
            "approval": approval,
            "risk_score": None if risk is None else risk.score,
            "detections": step_detections,
            "executed": executed,
        })
        agent_view = gw.for_agent()
        if approval == "rejected":
            agent_view = {**agent_view, "status": "rejected_by_user"}
        try:
            self._agent.observe(request, agent_view)
        except Exception:  # noqa: BLE001 - a broken agent stops the run
            self._finish("agent_error")

    def _finish(self, reason: str) -> None:
        if self._status in ("done",):
            return
        self._status = "done"
        self._stop_reason = reason

    def _grant_view(self) -> dict[str, Any]:
        g = self._stack.task.grant
        return {
            "tools": sorted(g.allowed_tools),
            "emails": sorted(g.allowed_email_ids),
            "files": sorted(g.allowed_file_ids),
            "recipients": sorted(g.allowed_recipients),
            "max_read_sensitivity": g.max_read_sensitivity.name.lower(),
        }

    @staticmethod
    def _args_view(request: object) -> Any:
        if isinstance(request, dict):
            return request.get("args")
        return {"_raw": str(request)[:200]}

    @staticmethod
    def _email_view(e: Any) -> dict[str, Any]:
        return {"id": e.id, "from": e.sender, "subject": e.subject,
                "body": e.body, "sensitivity": e.sensitivity.name.lower()}

    @staticmethod
    def _file_view(f: Any) -> dict[str, Any]:
        return {"id": f.id, "name": f.name, "sensitivity": f.sensitivity.name.lower(),
                "tags": list(f.tags)}

    @staticmethod
    def _msg_view(m: Any) -> dict[str, Any]:
        return {"id": m.id, "to": list(m.to), "subject": m.subject,
                "body": m.body, "attachments": list(m.attachments)}
