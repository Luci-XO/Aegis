"""Policy enforcement gateway: the only code path that executes tools.

Order of operations for every request:
1. Validate the untrusted request against the tool schema (P001/P002).
2. Evaluate deterministic policy (P003-P012). Any exception here is a denial (P000).
3. DENY: stop. An approval token cannot change this.
4. REQUIRE_APPROVAL: without a token, create an approval request and stop.
   With a token, redeem it against this exact action (A001-A008).
5. Write a pre-execution audit record. If that fails, do not execute (G001).
6. Execute the tool on the same validated object that was checked.
7. Update the session's data label and write the outcome record.

The agent only ever gets a GatewayResult. It cannot reach tool handlers directly.
"""

from __future__ import annotations

import enum
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from aegis.core.approvals import ApprovalService
from aegis.core.audit import AuditError, AuditLog
from aegis.core.clock import Clock, SystemClock
from aegis.core.policy import Policy, ResourceCatalog, evaluate
from aegis.core.rules import RULES
from aegis.core.schemas import Decision, Reason, RiskReport, ValidatedCall, Verdict
from aegis.core.session import SessionState
from aegis.tools.registry import TOOLS, ToolContext, ToolOutput
from aegis.tools.sandbox_env import SandboxEnv
from aegis.tools.validation import (
    ValidationError,
    parse_envelope,
    redact_args,
    safe_tool_label,
    validate_args,
)

log = logging.getLogger("aegis.gateway")

EvaluateFn = Callable[
    [ValidatedCall, SessionState, Policy, ResourceCatalog, "RiskReport | None", float], Decision
]


class Status(str, enum.Enum):
    EXECUTED = "executed"
    DENIED = "denied"
    PENDING_APPROVAL = "pending_approval"
    FAILED = "failed"  # allowed, but the tool raised; no effect was applied


@dataclass(frozen=True)
class GatewayResult:
    status: Status
    tool: str | None
    action_hash: str | None
    verdict: Verdict
    reasons: tuple[Reason, ...]
    output: dict[str, Any] | None = None
    approval_request_id: str | None = None
    latency_ms: float = 0.0

    @property
    def executed(self) -> bool:
        return self.status is Status.EXECUTED

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(r.rule_id for r in self.reasons)

    def for_agent(self) -> dict[str, Any]:
        """What the agent sees. A blocked action is reported as blocked."""
        msg: dict[str, Any] = {"status": self.status.value, "tool": self.tool}
        if self.output is not None:
            msg["result"] = self.output
        if self.status is not Status.EXECUTED:
            msg["rule_ids"] = list(self.rule_ids)
            msg["explanation"] = [r.message for r in self.reasons if r.verdict is not Verdict.ALLOW]
        if self.approval_request_id:
            msg["approval_request_id"] = self.approval_request_id
        return msg


@dataclass(frozen=True)
class ExecutionRecord:
    call: ValidatedCall
    approval_request_id: str | None
    at: float


@dataclass
class _Progress:
    executed: bool = False
    call: ValidatedCall | None = None
    output: ToolOutput | None = None
    approval_request_id: str | None = None


def _reason(rule_id: str, message: str | None = None, verdict: Verdict = Verdict.DENY) -> Reason:
    return Reason(rule_id, verdict, message or RULES[rule_id].description)


@dataclass
class Gateway:
    env: SandboxEnv
    policy: Policy
    approvals: ApprovalService
    audit: AuditLog
    clock: Clock = field(default_factory=SystemClock)
    evaluate_fn: EvaluateFn = evaluate
    trace: list[ExecutionRecord] = field(default_factory=list)

    def submit(
        self,
        raw: object,
        session: SessionState,
        risk: RiskReport | None = None,
        approval_token: str | None = None,
        case_id: str | None = None,
    ) -> GatewayResult:
        start = time.perf_counter()
        progress = _Progress()
        try:
            result = self._submit(raw, session, risk, approval_token, case_id, progress)
        except Exception:  # broad on purpose: fail closed on any unexpected error
            log.exception("gateway internal error; request denied")
            # If the tool already ran, report that truthfully.
            call = progress.call
            result = GatewayResult(
                status=Status.EXECUTED if progress.executed else Status.DENIED,
                tool=call.tool if call else safe_tool_label(raw),
                action_hash=call.action_hash if call else None,
                verdict=Verdict.DENY,
                reasons=(_reason("P000"),),
                output=progress.output.content if (progress.executed and progress.output) else None,
                approval_request_id=progress.approval_request_id,
            )
            self._audit_quiet("internal_error", session, case_id, result, risk, call)
        return replace(result, latency_ms=(time.perf_counter() - start) * 1000)

    # ------------------------------------------------------------------
    def _submit(
        self,
        raw: object,
        session: SessionState,
        risk: RiskReport | None,
        token: str | None,
        case_id: str | None,
        progress: _Progress,
    ) -> GatewayResult:
        # 1. Schema validation of untrusted input.
        try:
            tool, raw_args = parse_envelope(raw)
            spec = TOOLS.get(tool)
            if spec is None:
                return self._deny_early(session, case_id, risk, tool, "P001", f"unknown tool '{tool}'")
            args = validate_args(tool, raw_args, spec.args)
        except ValidationError as exc:
            return self._deny_early(session, case_id, risk, safe_tool_label(raw), "P002", str(exc))
        call = ValidatedCall.create(session.session_id, tool, args)
        progress.call = call

        # 2. Deterministic policy.
        now = self.clock.now()
        try:
            decision = self.evaluate_fn(call, session, self.policy, self.env, risk, now)
            if not isinstance(decision, Decision):
                raise TypeError("policy returned a non-Decision")
        except Exception:  # broad on purpose: any policy failure is a denial
            log.exception("policy evaluation failed; request denied")
            decision = Decision(Verdict.DENY, (_reason("P000"),), call.action_hash)

        # 3. Mandatory denial: nothing below can override it.
        if decision.verdict is Verdict.DENY:
            result = self._result(Status.DENIED, call, decision.verdict, decision.reasons)
            self._audit_strict("decision", session, case_id, result, risk, call)
            return result

        # 4. Approval.
        if decision.verdict is Verdict.REQUIRE_APPROVAL:
            if token is None:
                req = self.approvals.create(call, decision)
                result = self._result(
                    Status.PENDING_APPROVAL, call, decision.verdict, decision.reasons,
                    approval_request_id=req.request_id,
                )
                self._audit_strict("approval_requested", session, case_id, result, risk, call)
                return result
            redeemed = self.approvals.redeem(token, call)
            if not redeemed.ok:
                result = self._result(
                    Status.DENIED, call, Verdict.DENY,
                    decision.reasons + (_reason(redeemed.rule_id or "A002"),),
                    approval_request_id=redeemed.request_id,
                )
                self._audit_strict("approval_rejected", session, case_id, result, risk, call)
                return result
            progress.approval_request_id = redeemed.request_id

        # 5. Pre-execution audit record. No record, no execution.
        pre = self._result(
            Status.EXECUTED, call, decision.verdict, decision.reasons,
            approval_request_id=progress.approval_request_id,
        )
        try:
            self._audit_strict("execute_begin", session, case_id, pre, risk, call)
        except AuditError:
            return self._result(
                Status.DENIED, call, Verdict.DENY, decision.reasons + (_reason("G001"),),
                approval_request_id=progress.approval_request_id,
            )

        # 6. Execute exactly the validated call.
        try:
            output = TOOLS[call.tool].handler(self.env, call.args, ToolContext(grant=session.grant))
        except Exception:  # noqa: BLE001 - tool errors are reported as FAILED
            log.warning("tool %s raised; reported as failed", call.tool)
            result = self._result(
                Status.FAILED, call, decision.verdict, decision.reasons + (_reason("G002"),),
                approval_request_id=progress.approval_request_id,
            )
            self._audit_quiet("execute_failed", session, case_id, result, risk, call)
            return result
        progress.executed, progress.output = True, output

        # 7. Bookkeeping.
        at = self.clock.now()
        session._record_execution(call, output.label, progress.approval_request_id, at)
        self.trace.append(ExecutionRecord(call, progress.approval_request_id, at))
        result = self._result(
            Status.EXECUTED, call, decision.verdict, decision.reasons,
            output=output.content, approval_request_id=progress.approval_request_id,
        )
        self._audit_quiet("execute_done", session, case_id, result, risk, call)
        return result

    # ------------------------------------------------------------------
    @staticmethod
    def _result(
        status: Status,
        call: ValidatedCall,
        verdict: Verdict,
        reasons: tuple[Reason, ...],
        output: dict[str, Any] | None = None,
        approval_request_id: str | None = None,
    ) -> GatewayResult:
        return GatewayResult(
            status=status, tool=call.tool, action_hash=call.action_hash, verdict=verdict,
            reasons=reasons, output=output, approval_request_id=approval_request_id,
        )

    def _deny_early(
        self, session: SessionState, case_id: str | None, risk: RiskReport | None,
        tool: str | None, rule_id: str, message: str,
    ) -> GatewayResult:
        result = GatewayResult(
            status=Status.DENIED, tool=tool, action_hash=None, verdict=Verdict.DENY,
            reasons=(_reason(rule_id, message),),
        )
        self._audit_quiet("decision", session, case_id, result, risk, None)
        return result

    def _record(
        self, event: str, session: SessionState, case_id: str | None,
        result: GatewayResult, risk: RiskReport | None, call: ValidatedCall | None,
    ) -> dict[str, Any]:
        return {
            "ts": self.clock.now(),
            "event": event,
            "session_id": session.session_id,
            "task_id": session.grant.task_id,
            "case_id": case_id,
            "policy_version": self.policy.version,
            "tool": result.tool,
            "action_hash": result.action_hash,
            "args_summary": redact_args(call.args, TOOLS[call.tool].args) if call else None,
            "status": result.status.value,
            "verdict": result.verdict.name,
            "rule_ids": list(result.rule_ids),
            "approval_request_id": result.approval_request_id,
            "risk_score": None if risk is None else risk.score,
            "detector": None if risk is None else risk.detector,
            "session_label": session.label.name,
        }

    def _audit_strict(self, event, session, case_id, result, risk, call) -> None:
        self.audit.append(self._record(event, session, case_id, result, risk, call))

    def _audit_quiet(self, event, session, case_id, result, risk, call) -> None:
        # Used only where the security outcome is already fixed (a denial, or a
        # completed execution whose execute_begin record already exists).
        try:
            self._audit_strict(event, session, case_id, result, risk, call)
        except Exception:  # noqa: BLE001 - outcome already fixed; do not mask it
            log.error("audit write failed for event %s", event)
