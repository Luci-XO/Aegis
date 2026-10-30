"""Deterministic policy engine.

`evaluate` is a pure function of (validated call, session state, grant, policy,
resource catalogue, detector report, time). It has no LLM dependency and no I/O.
Every reason it returns carries a rule ID from `aegis.core.rules`.

How the risk score is used: it can only raise a verdict (ALLOW to
REQUIRE_APPROVAL) and only for external side effects. It can never lower a
verdict, so a detector that labels an attack "safe" cannot unlock a denied action.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Protocol

from aegis.core.schemas import (
    Decision,
    Effect,
    Reason,
    RiskReport,
    Sensitivity,
    ValidatedCall,
    Verdict,
)
from aegis.core.session import SessionState
from aegis.tools.registry import TOOLS, ToolSpec


class PolicyError(ValueError):
    """The policy file is invalid. The gateway refuses to start with it."""


class ResourceCatalog(Protocol):
    def email_sensitivity(self, email_id: str) -> Sensitivity | None: ...
    def file_sensitivity(self, file_id: str) -> Sensitivity | None: ...


@dataclass(frozen=True)
class ToolPolicy:
    enabled: bool
    require_approval: bool


@dataclass(frozen=True)
class Policy:
    version: str
    org_domains: frozenset[str]
    tools: Mapping[str, ToolPolicy]
    egress: Mapping[str, Mapping[Sensitivity, Verdict]]  # "internal"/"external" -> label -> verdict
    escalation_threshold: float
    escalate_when_detector_unavailable: bool

    @staticmethod
    def from_dict(data: object) -> Policy:
        def expect_keys(obj: object, keys: set[str], where: str) -> Mapping:
            if not isinstance(obj, Mapping) or set(obj.keys()) != keys:
                raise PolicyError(f"{where}: expected exactly the keys {sorted(keys)}")
            return obj

        d = expect_keys(data, {"version", "org_domains", "tools", "egress", "risk"}, "policy")
        if not isinstance(d["version"], str) or not d["version"]:
            raise PolicyError("version must be a non-empty string")

        domains = d["org_domains"]
        if not isinstance(domains, list) or not domains or not all(
            isinstance(x, str) and x == x.lower() and "." in x for x in domains
        ):
            raise PolicyError("org_domains must be a non-empty list of lower-case domains")

        raw_tools = d["tools"]
        if not isinstance(raw_tools, Mapping):
            raise PolicyError("tools must be an object")
        tools: dict[str, ToolPolicy] = {}
        for name, cfg in raw_tools.items():
            if name not in TOOLS:
                raise PolicyError(f"tools: '{name}' is not a registered tool")
            cfg = expect_keys(cfg, {"enabled", "require_approval"}, f"tools.{name}")
            if not all(isinstance(cfg[k], bool) for k in cfg):
                raise PolicyError(f"tools.{name}: values must be booleans")
            tools[name] = ToolPolicy(cfg["enabled"], cfg["require_approval"])

        raw_egress = expect_keys(d["egress"], {"internal", "external"}, "egress")
        egress: dict[str, dict[Sensitivity, Verdict]] = {}
        for dest, table in raw_egress.items():
            table = expect_keys(table, {"public", "internal", "confidential"}, f"egress.{dest}")
            try:
                egress[dest] = {Sensitivity.parse(k): Verdict.parse(v) for k, v in table.items()}
            except ValueError as exc:
                raise PolicyError(f"egress.{dest}: {exc}") from None
        # Non-negotiable floor: no policy file may allow confidential data to leave
        # the organisation without at least human approval.
        if egress["external"][Sensitivity.CONFIDENTIAL] == Verdict.ALLOW:
            raise PolicyError("egress.external.confidential may not be 'allow'")

        risk = expect_keys(
            d["risk"], {"escalation_threshold", "escalate_when_detector_unavailable"}, "risk"
        )
        threshold = risk["escalation_threshold"]
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not 0 <= threshold <= 1:
            raise PolicyError("risk.escalation_threshold must be a number in [0, 1]")
        if not isinstance(risk["escalate_when_detector_unavailable"], bool):
            raise PolicyError("risk.escalate_when_detector_unavailable must be a boolean")

        return Policy(
            version=d["version"],
            org_domains=frozenset(domains),
            tools=tools,
            egress=egress,
            escalation_threshold=float(threshold),
            escalate_when_detector_unavailable=risk["escalate_when_detector_unavailable"],
        )

    @staticmethod
    def load(path: str | Path | None = None) -> Policy:
        if path is None:
            text = (resources.files("aegis") / "policies" / "default.json").read_text("utf-8")
        else:
            text = Path(path).read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"policy is not valid JSON: {exc}") from None
        return Policy.from_dict(data)

    def is_internal_address(self, address: str) -> bool:
        # Exact domain match only. "aegis-corp.example.evil.example" and
        # "aegis-c0rp.example" are both external.
        return address.rsplit("@", 1)[-1] in self.org_domains


def _r(rule_id: str, verdict: Verdict, message: str) -> Reason:
    return Reason(rule_id=rule_id, verdict=verdict, message=message)


def evaluate(
    call: ValidatedCall,
    session: SessionState,
    policy: Policy,
    catalog: ResourceCatalog,
    risk: RiskReport | None,
    now: float,
) -> Decision:
    grant = session.grant
    spec: ToolSpec | None = TOOLS.get(call.tool)
    tool_policy = policy.tools.get(call.tool)
    reasons: list[Reason] = []
    deny, approve = Verdict.DENY, Verdict.REQUIRE_APPROVAL

    if call.session_id != session.session_id:
        return Decision.from_reasons([_r("P000", deny, "call bound to a different session")], call.action_hash)
    if spec is None or tool_policy is None or not tool_policy.enabled:
        return Decision.from_reasons([_r("P001", deny, f"tool '{call.tool}' is not enabled")], call.action_hash)
    if grant.expires_at is not None and now >= grant.expires_at:
        reasons.append(_r("P004", deny, "task grant has expired"))
    if call.tool not in grant.allowed_tools:
        reasons.append(_r("P003", deny, f"task '{grant.task_id}' does not grant '{call.tool}'"))

    # Resources: every referenced email/file must exist, be granted, and be
    # within the grant's sensitivity clearance.
    touched: list[Sensitivity] = []
    for arg, kind in spec.resource_args.items():
        value = call.args.get(arg, ())
        for rid in value if isinstance(value, tuple) else (value,):
            if kind == "email":
                level, allowed = catalog.email_sensitivity(rid), grant.allowed_email_ids
            else:
                level, allowed = catalog.file_sensitivity(rid), grant.allowed_file_ids
            if level is None or rid not in allowed:
                reasons.append(_r("P005", deny, f"{kind} '{rid}' is not available to this task"))
                continue
            touched.append(level)
            if level > grant.max_read_sensitivity:
                reasons.append(_r("P006", deny, f"{kind} '{rid}' is {level.name.lower()}, above task clearance"))

    if spec.effect is Effect.EXTERNAL_SIDE_EFFECT:
        recipients = call.args.get(spec.recipient_arg or "", ())
        if not isinstance(recipients, tuple) or not recipients:
            # Unreachable after schema validation; deny rather than assume.
            raise TypeError("external side-effect tool without recipients")
        for rcpt in recipients:
            if rcpt not in grant.allowed_recipients:
                reasons.append(_r("P007", deny, f"recipient domain '{rcpt.rsplit('@', 1)[-1]}' is not granted for this task"))

        # Data label of the outgoing message: what the session has seen, plus attachments.
        label = max([session.label, *touched])
        external = any(not policy.is_internal_address(r) for r in recipients)
        dest = "external" if external else "internal"
        flow = policy.egress[dest][label]
        if flow is not Verdict.ALLOW:
            rule = "P008" if flow is deny else "P009"
            reasons.append(_r(rule, flow, f"{label.name.lower()} data to {dest} recipient: {flow.name.lower()}"))

        if tool_policy.require_approval:
            reasons.append(_r("P010", approve, f"policy requires approval for '{call.tool}'"))

        if risk is None:
            if policy.escalate_when_detector_unavailable:
                reasons.append(_r("P012", approve, "detector result unavailable"))
        elif risk.score >= policy.escalation_threshold:
            reasons.append(_r("P011", approve, f"detector risk {risk.score:.2f} >= {policy.escalation_threshold:.2f}"))

    return Decision.from_reasons(reasons, call.action_hash)
