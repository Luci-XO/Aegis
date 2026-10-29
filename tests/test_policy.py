"""Policy rules and policy-file validation."""

from __future__ import annotations

import copy
import json
from importlib import resources

import pytest

from aegis.core.policy import Policy, PolicyError, evaluate
from aegis.core.schemas import RiskReport, Sensitivity, ValidatedCall, Verdict
from aegis.tools.registry import TOOLS
from aegis.tools.validation import validate_args
from tests.conftest import INTERNAL_USER, make_grant, session

NOW = 1_800_000_000.0


def vc(s, tool, **args):
    return ValidatedCall.create(s.session_id, tool, validate_args(tool, args, TOOLS[tool].args))


def msg(to, attachments=()):
    return {"to": list(to), "subject": "s", "body": "b", "attachments": list(attachments)}


def decide(s, tool, risk=RiskReport(0.0), **args):
    from aegis.tools.sandbox_env import SandboxEnv

    return evaluate(vc(s, tool, **args), s, Policy.load(), SandboxEnv.default(), risk, NOW)


# --- reads -----------------------------------------------------------------

def test_granted_read_is_allowed():
    d = decide(session(), "read_email", email_id="e-001")
    assert d.verdict is Verdict.ALLOW and d.rule_ids == ()


def test_tool_not_in_grant_is_denied():
    d = decide(session(make_grant(tools=("read_email",))), "read_file", file_id="f-001")
    assert d.verdict is Verdict.DENY and "P003" in d.rule_ids


def test_resource_outside_grant_is_denied():
    d = decide(session(make_grant(files=("f-001",))), "read_file", file_id="f-002")
    assert d.verdict is Verdict.DENY and "P005" in d.rule_ids


def test_nonexistent_resource_is_denied():
    d = decide(session(make_grant(files=("f-999",))), "read_file", file_id="f-999")
    assert d.verdict is Verdict.DENY and "P005" in d.rule_ids


def test_sensitivity_above_clearance_is_denied():
    d = decide(session(make_grant(max_read=Sensitivity.INTERNAL)), "read_file", file_id="f-002")
    assert d.verdict is Verdict.DENY and "P006" in d.rule_ids


def test_expired_grant_is_denied():
    d = decide(session(make_grant(expires_at=NOW - 1)), "read_email", email_id="e-001")
    assert d.verdict is Verdict.DENY and "P004" in d.rule_ids


# --- egress ----------------------------------------------------------------

def test_send_always_needs_approval():
    s = session(make_grant(recipients=(INTERNAL_USER,)))
    d = decide(s, "send_email", **msg([INTERNAL_USER]))
    assert d.verdict is Verdict.REQUIRE_APPROVAL and d.rule_ids == ("P010",)


def test_recipient_not_granted_is_denied():
    s = session(make_grant(recipients=(INTERNAL_USER,)))
    d = decide(s, "send_email", **msg(["attacker@evil.example"]))
    assert d.verdict is Verdict.DENY and "P007" in d.rule_ids


def test_confidential_attachment_to_external_is_denied_even_if_recipient_granted():
    ext = "editor@techdaily.example"
    s = session(make_grant(recipients=(ext,)))
    d = decide(s, "send_email", **msg([ext], attachments=["f-002"]))
    assert d.verdict is Verdict.DENY and "P008" in d.rule_ids


def test_confidential_attachment_to_internal_needs_approval():
    s = session(make_grant(recipients=(INTERNAL_USER,)))
    d = decide(s, "send_email", **msg([INTERNAL_USER], attachments=["f-002"]))
    assert d.verdict is Verdict.REQUIRE_APPROVAL and {"P009", "P010"} <= set(d.rule_ids)


def test_public_attachment_to_external_needs_only_send_approval():
    ext = "editor@techdaily.example"
    s = session(make_grant(recipients=(ext,)))
    d = decide(s, "send_email", **msg([ext], attachments=["f-003"]))
    assert d.verdict is Verdict.REQUIRE_APPROVAL and d.rule_ids == ("P010",)


def test_lookalike_and_suffix_domains_are_external():
    p = Policy.load()
    assert p.is_internal_address("maya.chen@aegis-corp.example")
    assert not p.is_internal_address("it-helpdesk@aegis-c0rp.example")
    assert not p.is_internal_address("x@aegis-corp.example.evil.example")
    assert not p.is_internal_address("x@sub.aegis-corp.example")


# --- detector interaction --------------------------------------------------

def test_high_risk_escalates_side_effects_only():
    s = session(make_grant(recipients=(INTERNAL_USER,)))
    hi = RiskReport(0.9)
    assert decide(s, "read_email", risk=hi, email_id="e-002").verdict is Verdict.ALLOW
    assert "P011" in decide(s, "send_email", risk=hi, **msg([INTERNAL_USER])).rule_ids


def test_missing_detector_escalates_side_effects():
    s = session(make_grant(recipients=(INTERNAL_USER,)))
    assert "P012" in decide(s, "send_email", risk=None, **msg([INTERNAL_USER])).rule_ids


@pytest.mark.parametrize("score", [0.0, 0.3, 0.5, 0.99, 1.0, None])
def test_risk_score_never_lowers_a_denial(score):
    risk = None if score is None else RiskReport(score)
    s = session(make_grant(recipients=("audit@finance-review.example",)))
    d = decide(s, "send_email", risk=risk, **msg(["audit@finance-review.example"], ["f-002"]))
    assert d.verdict is Verdict.DENY


# --- policy file validation ------------------------------------------------

def _default() -> dict:
    return json.loads((resources.files("aegis") / "policies" / "default.json").read_text("utf-8"))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p["egress"]["external"].__setitem__("confidential", "allow"),  # floor
        lambda p: p["tools"].__setitem__("shell", {"enabled": True, "require_approval": False}),
        lambda p: p["tools"]["send_email"].__setitem__("require_approval", "no"),
        lambda p: p["egress"]["internal"].pop("public"),
        lambda p: p["egress"]["external"].__setitem__("internal", "maybe"),
        lambda p: p.__setitem__("org_domains", []),
        lambda p: p.__setitem__("extra", 1),
        lambda p: p["risk"].__setitem__("escalation_threshold", 2),
    ],
)
def test_invalid_policies_are_rejected(mutate):
    p = copy.deepcopy(_default())
    mutate(p)
    with pytest.raises(PolicyError):
        Policy.from_dict(p)


def test_default_policy_loads():
    assert Policy.load().version == _default()["version"]
