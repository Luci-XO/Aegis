"""Comparison executors with the same interface as `Gateway.submit`.

Baseline A (unprotected): the tool API checks argument types (a real tool
would too) and then runs anything. The agent acts with the user's full
permissions: every email, every file, any recipient, no approval.

Baseline B (detector-only): like A, but an external side effect (sending
email) is blocked when the session's aggregated detector score is at or above
the threshold, or when the detector gave no result. Blocking on "no result"
is the stricter, fail-closed choice, so B is not a straw man.

Neither baseline creates approval requests (`approvals` is None).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace

from aegis.core.clock import Clock, SystemClock
from aegis.core.gateway import ExecutionRecord, GatewayResult, Status, _reason
from aegis.core.schemas import Effect, RiskReport, Sensitivity, TaskGrant, ValidatedCall, Verdict
from aegis.core.session import SessionState
from aegis.tools.registry import TOOLS, ToolContext
from aegis.tools.sandbox_env import SandboxEnv
from aegis.tools.validation import ValidationError, parse_envelope, safe_tool_label, validate_args


def full_access_grant(env: SandboxEnv) -> TaskGrant:
    """The user's own permissions, used as the tool context for baselines."""
    return TaskGrant(
        task_id="full_access",
        allowed_tools=frozenset(TOOLS),
        allowed_email_ids=frozenset(env.emails),
        allowed_file_ids=frozenset(env.files),
        max_read_sensitivity=Sensitivity.CONFIDENTIAL,
    )


@dataclass
class UnprotectedExecutor:
    env: SandboxEnv
    clock: Clock = field(default_factory=SystemClock)
    block_side_effects_at: float | None = None  # set for baseline B
    trace: list[ExecutionRecord] = field(default_factory=list)
    approvals: None = None

    @property
    def kind(self) -> str:
        return "detector_only" if self.block_side_effects_at is not None else "unprotected"

    def submit(
        self,
        raw: object,
        session: SessionState,
        risk: RiskReport | None = None,
        approval_token: str | None = None,
        case_id: str | None = None,
    ) -> GatewayResult:
        start = time.perf_counter()
        result = self._submit(raw, session, risk)
        return replace(result, latency_ms=(time.perf_counter() - start) * 1000)

    def _submit(self, raw: object, session: SessionState, risk: RiskReport | None) -> GatewayResult:
        try:
            tool, raw_args = parse_envelope(raw)
            spec = TOOLS.get(tool)
            if spec is None:
                return self._denied(tool, None, "P001")
            args = validate_args(tool, raw_args, spec.args)
        except ValidationError:
            return self._denied(safe_tool_label(raw), None, "P002")
        call = ValidatedCall.create(session.session_id, tool, args)

        if (
            self.block_side_effects_at is not None
            and spec.effect is Effect.EXTERNAL_SIDE_EFFECT
            and (risk is None or risk.score >= self.block_side_effects_at)
        ):
            return self._denied(tool, call, "B01")

        try:
            out = spec.handler(self.env, call.args, ToolContext(grant=full_access_grant(self.env)))
        except Exception:  # noqa: BLE001 - report as failed, like the gateway
            return GatewayResult(Status.FAILED, tool, call.action_hash, Verdict.ALLOW, (_reason("G002"),))
        at = self.clock.now()
        session._record_execution(call, out.label, None, at)
        self.trace.append(ExecutionRecord(call, None, at))
        return GatewayResult(Status.EXECUTED, tool, call.action_hash, Verdict.ALLOW, (), output=out.content)

    @staticmethod
    def _denied(tool: str | None, call: ValidatedCall | None, rule: str) -> GatewayResult:
        return GatewayResult(
            Status.DENIED, tool, call.action_hash if call else None, Verdict.DENY, (_reason(rule),))
