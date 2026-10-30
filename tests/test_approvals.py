"""Approvals are bound to one exact action, single-use, session-bound and expiring."""

from __future__ import annotations

import pytest

from aegis.core.approvals import ApprovalError, ApprovalService, ApprovalStatus, load_secret
from aegis.core.gateway import Status
from tests.conftest import INTERNAL_USER, SAFE, call, make_grant, send, session

RAJ = "raj.patel@aegis-corp.example"
EDITOR = "editor@techdaily.example"


def _approved(gateway, s, req):
    pending = gateway.submit(req, s, risk=SAFE)
    assert pending.status is Status.PENDING_APPROVAL
    return pending, gateway.approvals.approve(pending.approval_request_id)


@pytest.fixture
def s():
    return session(make_grant(recipients=(RAJ, INTERNAL_USER, EDITOR)))


BASE = send([RAJ], body="Agenda attached", attachments=["f-007"])


@pytest.mark.parametrize(
    "changed",
    [
        send([INTERNAL_USER], body="Agenda attached", attachments=["f-007"]),   # recipient
        send([RAJ, INTERNAL_USER], body="Agenda attached", attachments=["f-007"]),  # extra recipient
        send([RAJ], body="Agenda attached!", attachments=["f-007"]),            # body
        send([RAJ], body="Agenda attached", attachments=["f-001"]),             # attachment
        send([RAJ], body="Agenda attached", attachments=[]),                    # removed attachment
        send([RAJ], subject="Other", body="Agenda attached", attachments=["f-007"]),
    ],
)
def test_changed_parameters_invalidate_approval(gateway, env, s, changed):
    pending, token = _approved(gateway, s, BASE)
    r = gateway.submit(changed, s, risk=SAFE, approval_token=token)
    assert r.status is Status.DENIED and "A008" in r.rule_ids
    assert env.outbox == []
    # The approval is revoked: the original action cannot use it either.
    assert gateway.approvals.get(pending.approval_request_id).status is ApprovalStatus.REVOKED
    again = gateway.submit(BASE, s, risk=SAFE, approval_token=token)
    assert again.status is Status.DENIED and env.outbox == []


def test_token_is_single_use(gateway, env, s):
    _, token = _approved(gateway, s, BASE)
    assert gateway.submit(BASE, s, risk=SAFE, approval_token=token).executed
    replay = gateway.submit(BASE, s, risk=SAFE, approval_token=token)
    assert replay.status is Status.DENIED and "A005" in replay.rule_ids
    assert len(env.outbox) == 1


def test_expired_approval_is_rejected(gateway, env, s, clock):
    _, token = _approved(gateway, s, BASE)
    clock.advance(301)
    r = gateway.submit(BASE, s, risk=SAFE, approval_token=token)
    assert r.status is Status.DENIED and "A006" in r.rule_ids and env.outbox == []


def test_cannot_approve_after_expiry(gateway, s, clock):
    pending = gateway.submit(BASE, s, risk=SAFE)
    clock.advance(301)
    with pytest.raises(ApprovalError):
        gateway.approvals.approve(pending.approval_request_id)


def test_token_from_another_session_is_rejected(gateway, env, s):
    _, token = _approved(gateway, s, BASE)
    other = session(s.grant, sid="s-other")
    r = gateway.submit(BASE, other, risk=SAFE, approval_token=token)
    assert r.status is Status.DENIED and "A007" in r.rule_ids and env.outbox == []


@pytest.mark.parametrize("bad", ["", "nodot", "a.b.c", "0" * 32 + "." + "f" * 64, 12345, "x" * 500])
def test_forged_or_malformed_tokens_are_rejected(gateway, env, s, bad):
    gateway.submit(BASE, s, risk=SAFE)  # create a pending request
    r = gateway.submit(BASE, s, risk=SAFE, approval_token=bad)
    assert r.status is Status.DENIED and r.rule_ids[-1] in {"A001", "A002"}
    assert env.outbox == []


def test_tampered_signature_is_rejected(gateway, env, s):
    pending, token = _approved(gateway, s, BASE)
    rid, mac = token.split(".")
    forged = f"{rid}.{'0' if mac[0] != '0' else '1'}{mac[1:]}"
    r = gateway.submit(BASE, s, risk=SAFE, approval_token=forged)
    assert r.status is Status.DENIED and "A003" in r.rule_ids and env.outbox == []


def test_unapproved_request_id_cannot_be_used_as_token(gateway, env, s):
    pending = gateway.submit(BASE, s, risk=SAFE)
    mac = gateway.approvals._mac(gateway.approvals.get(pending.approval_request_id))
    r = gateway.submit(BASE, s, risk=SAFE, approval_token=f"{pending.approval_request_id}.{mac}")
    assert r.status is Status.DENIED and "A004" in r.rule_ids and env.outbox == []


def test_rejected_request_cannot_be_redeemed(gateway, env, s):
    pending, token = _approved(gateway, s, BASE)
    gateway.approvals.reject(pending.approval_request_id)
    r = gateway.submit(BASE, s, risk=SAFE, approval_token=token)
    assert r.status is Status.DENIED and "A004" in r.rule_ids and env.outbox == []


def test_approval_never_overrides_a_later_policy_denial(gateway, env, s):
    """Approve an internal-label send to an external address, then read confidential
    data before redeeming. Policy is re-evaluated at redemption and now denies."""
    req = send([EDITOR], body="Press release attached", attachments=["f-003"])
    assert gateway.submit(call("read_email", email_id="e-005"), s, risk=SAFE).executed
    _, token = _approved(gateway, s, req)
    assert gateway.submit(call("read_file", file_id="f-002"), s, risk=SAFE).executed
    r = gateway.submit(req, s, risk=SAFE, approval_token=token)
    assert r.status is Status.DENIED and "P008" in r.rule_ids
    assert env.outbox == []


def test_approval_display_shows_real_parameters(gateway, s):
    pending = gateway.submit(BASE, s, risk=SAFE)
    shown = gateway.approvals.get(pending.approval_request_id).display
    assert shown == {"tool": "send_email", "args": {
        "to": [RAJ], "subject": "Hi", "body": "Agenda attached", "attachments": ["f-007"]}}


def test_secret_loading():
    assert len(load_secret({"AEGIS_APPROVAL_SECRET": "ab" * 32})) == 32
    with pytest.raises(ValueError):
        load_secret({"AEGIS_APPROVAL_SECRET": "ab" * 8})
    with pytest.raises(ValueError):
        load_secret({"AEGIS_APPROVAL_SECRET": "not-hex"})
    with pytest.warns(UserWarning):
        assert len(load_secret({})) == 32
    with pytest.raises(ValueError):
        ApprovalService(b"short")
