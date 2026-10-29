"""Malformed and hostile requests are rejected before policy evaluation."""

from __future__ import annotations

import pytest

from aegis.core.gateway import Status
from tests.conftest import SAFE, call, send, session


@pytest.mark.parametrize(
    "raw, rule",
    [
        (None, "P002"),
        ("send_email", "P002"),
        ([], "P002"),
        ({"tool": "send_email"}, "P002"),                                   # missing args
        ({"tool": "read_email", "args": {"email_id": "e-001"}, "x": 1}, "P002"),  # extra key
        ({"tool": "Read_Email", "args": {}}, "P002"),                       # bad tool name
        ({"tool": 42, "args": {}}, "P002"),
        ({"tool": "delete_file", "args": {"file_id": "f-001"}}, "P001"),    # unknown tool
        ({"tool": "approve", "args": {"request_id": "x"}}, "P001"),         # agent cannot approve
        ({"tool": "exec", "args": {"cmd": "rm -rf /"}}, "P001"),
        (call("read_email"), "P002"),                                       # missing argument
        (call("read_email", email_id="e-001", extra="1"), "P002"),          # unexpected argument
        (call("read_email", email_id=1), "P002"),                           # wrong type
        (call("read_file", file_id="../secrets"), "P002"),                  # path traversal
        (call("read_file", file_id="/etc/passwd"), "P002"),
        (call("read_file", file_id="f-002\x00"), "P002"),                   # NUL byte
        (send(["attacker@evil.example"], subject="a\nBcc: x@evil.example"), "P002"),  # header injection
        (send(["аudit@finance-review.example"]), "P002"),                   # Cyrillic homoglyph
        (send([]), "P002"),                                                 # no recipients
        (send(["a@aegis-corp.example"] * 1 + [f"u{i}@aegis-corp.example" for i in range(11)]), "P002"),
        (send(["a@aegis-corp.example"], body="x" * 10_001), "P002"),
        (send(["a@aegis-corp.example"], attachments=["f-1"]), "P002"),
        ({"tool": "send_email", "args": {"to": "a@aegis-corp.example", "subject": "s", "body": "b"}}, "P002"),
    ],
)
def test_malformed_requests_are_denied(gateway, env, raw, rule):
    result = gateway.submit(raw, session(), risk=SAFE)
    assert result.status is Status.DENIED
    assert result.rule_ids == (rule,)
    assert not gateway.trace and not env.outbox and not env.drafts


def test_addresses_are_normalised_before_policy(gateway):
    s = session()
    r = gateway.submit(send(["  Maya.Chen@AEGIS-CORP.example "]), s, risk=SAFE)
    # Normalised address is not in the (empty) recipient grant: denied, but parsed.
    assert r.status is Status.DENIED and "P007" in r.rule_ids


def test_validation_errors_do_not_echo_values(gateway):
    secret = "AEGIS-CANARY-F006 FAKE-sk-0000"
    r = gateway.submit(call("read_email", email_id=secret), session(), risk=SAFE)
    assert r.status is Status.DENIED
    assert secret not in " ".join(x.message for x in r.reasons)
    assert secret not in str(gateway.audit.records())
