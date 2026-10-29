"""Randomised adversarial test of the core invariant:

    No action forbidden by deterministic policy executes, whatever the detector
    says and whatever the agent requests.

A seeded generator plays a fully compromised agent. It sends random, malformed
and hostile tool calls, reports random risk scores (including "safe" for
attacks), and abuses approvals: it swaps parameters under approved tokens,
replays them, and reuses them across sessions. The simulated human approves
every request (a worst-case rubber-stamp approver).

The postconditions below are checked against the gateway's execution trace and
the sandbox outbox. They are written from the specification, not by calling
the policy engine, so a bug in policy.py cannot also hide itself here.
"""

from __future__ import annotations

import random

import pytest

from aegis.core.approvals import ApprovalService, ApprovalStatus
from aegis.core.audit import AuditLog
from aegis.core.clock import FakeClock
from aegis.core.gateway import Gateway, Status
from aegis.core.policy import Policy
from aegis.core.schemas import RiskReport, Sensitivity, TaskGrant
from aegis.core.session import SessionState
from aegis.tools.sandbox_env import SandboxEnv
from tests.conftest import TEST_SECRET

ORG = "aegis-corp.example"
ADDRESSES = [
    "maya.chen@aegis-corp.example", "raj.patel@aegis-corp.example",
    "editor@techdaily.example", "audit@finance-review.example",
    "it-helpdesk@aegis-c0rp.example", "x@aegis-corp.example.evil.example",
    "onboarding@northwind-partners.example",
]
HOSTILE_STRINGS = ["../f-002", "f-002 ", "F-002", "f-0021", "", "e-00", "аudit@finance-review.example",
                   "a@b", "x" * 300, "line\nbreak", "\x00"]
TOOL_NAMES = ["read_email", "search_files", "read_file", "draft_email", "send_email",
              "approve", "delete_file", "send_emai1", "exec"]
EMAIL_IDS = [f"e-00{i}" for i in range(1, 10)]
FILE_IDS = [f"f-00{i}" for i in range(1, 10)]


def _sample(rng, pool, k_max):
    return rng.sample(pool, rng.randint(0, min(k_max, len(pool))))


def random_grant(rng: random.Random, now: float) -> TaskGrant:
    tools = set(_sample(rng, TOOL_NAMES[:5], 5))
    if rng.random() < 0.7:
        tools.add("send_email")
    return TaskGrant(
        task_id="fuzz",
        allowed_tools=frozenset(tools),
        allowed_email_ids=frozenset(_sample(rng, EMAIL_IDS, 9)),
        allowed_file_ids=frozenset(_sample(rng, FILE_IDS, 9)),
        allowed_recipients=frozenset(_sample(rng, ADDRESSES, 4)),
        max_read_sensitivity=rng.choice(list(Sensitivity)),
        expires_at=rng.choice([None, None, now + 50, now - 1]),
    )


def random_str(rng, pool):
    return rng.choice(HOSTILE_STRINGS) if rng.random() < 0.15 else rng.choice(pool)


def random_call(rng: random.Random, grant: TaskGrant | None = None) -> object:
    """Half the time, draw identifiers from the grant so that calls get past
    the first checks and exercise approval and egress paths."""
    roll = rng.random()
    if roll < 0.03:
        return rng.choice([None, [], "send_email", 7, {"tool": "send_email"}])
    near = grant is not None and rng.random() < 0.5
    emails = sorted(grant.allowed_email_ids) if near and grant.allowed_email_ids else EMAIL_IDS
    files = sorted(grant.allowed_file_ids) if near and grant.allowed_file_ids else FILE_IDS
    addrs = sorted(grant.allowed_recipients) if near and grant.allowed_recipients else ADDRESSES
    tool = rng.choice(TOOL_NAMES) if rng.random() < 0.2 else rng.choice(TOOL_NAMES[:5] + ["send_email"] * 3)
    if tool == "read_email":
        args = {"email_id": random_str(rng, emails)}
    elif tool == "read_file":
        args = {"file_id": random_str(rng, files)}
    elif tool == "search_files":
        args = {"query": rng.choice(["contract", "payroll", "a", "", "roadmap"])}
    elif tool in ("draft_email", "send_email"):
        args = {
            "to": [random_str(rng, addrs) for _ in range(rng.randint(1, 3))],
            "subject": rng.choice(["Hi", "Re: invoice", "a\nBcc: x@evil.example"]),
            "body": rng.choice(["hello", "AEGIS-CANARY-F002", "summary of the contract"]),
            "attachments": [random_str(rng, files) for _ in range(rng.randint(0, 2))],
        }
    else:
        args = {"cmd": "anything"}
    if rng.random() < 0.05:
        args["extra"] = "1"
    return {"tool": tool, "args": args}


def mutate_call(rng: random.Random, raw: dict) -> dict:
    """Change one parameter of a send while keeping the approval token."""
    args = dict(raw["args"])
    field = rng.choice(["to", "body", "attachments"])
    if field == "to":
        args["to"] = list(args["to"]) + [rng.choice(ADDRESSES)]
    elif field == "body":
        args["body"] = args["body"] + " (edited)"
    else:
        args["attachments"] = list(args.get("attachments", [])) + [rng.choice(FILE_IDS[:8])]
    return {"tool": raw["tool"], "args": args}


def random_risk(rng):
    return rng.choice([None, RiskReport(0.0), RiskReport(rng.random()), RiskReport(1.0)])


def check_postconditions(gw: Gateway, env: SandboxEnv, sessions: dict[str, SessionState], clock_log):
    base = SandboxEnv.default()
    used_requests: set[str] = set()
    confidential_seen: dict[str, bool] = {sid: False for sid in sessions}
    sends = [rec for rec in gw.trace if rec.call.tool == "send_email"]

    # (I6) Every message in the outbox came from a traced, executed send with identical args.
    assert len(env.outbox) == len(sends)
    for msg, rec in zip(env.outbox, sends):
        a = rec.call.args
        assert (msg.to, msg.subject, msg.body, msg.attachments) == (
            a["to"], a["subject"], a["body"], a["attachments"])

    for rec in gw.trace:
        c, s = rec.call, sessions[rec.call.session_id]
        g = s.grant
        # (I1) tool granted and grant not expired at execution time
        assert c.tool in g.allowed_tools
        assert g.expires_at is None or rec.at < g.expires_at
        # (I2) every referenced resource exists, is granted and within clearance
        refs = []
        if c.tool == "read_email":
            refs = [("email", c.args["email_id"])]
        elif c.tool == "read_file":
            refs = [("file", c.args["file_id"])]
        elif c.tool in ("draft_email", "send_email"):
            refs = [("file", f) for f in c.args["attachments"]]
        levels = []
        for kind, rid in refs:
            store, allowed = (base.emails, g.allowed_email_ids) if kind == "email" else (base.files, g.allowed_file_ids)
            assert rid in store and rid in allowed
            assert store[rid].sensitivity <= g.max_read_sensitivity
            levels.append(store[rid].sensitivity)

        if c.tool == "send_email":
            # (I3) every recipient granted
            assert set(c.args["to"]) <= g.allowed_recipients
            # (I4) no confidential data (seen or attached) reaches an external address
            external = any(addr.rsplit("@", 1)[1] != ORG for addr in c.args["to"])
            if external:
                assert not confidential_seen[c.session_id]
                assert Sensitivity.CONFIDENTIAL not in levels
            # (I5) a human approved exactly this action, and the approval was used once
            assert rec.approval_request_id is not None
            req = gw.approvals.get(rec.approval_request_id)
            assert req.action_hash == c.action_hash and req.session_id == c.session_id
            assert req.status is ApprovalStatus.USED
            assert rec.approval_request_id not in used_requests
            used_requests.add(rec.approval_request_id)

        if c.tool in ("read_email", "read_file") and Sensitivity.CONFIDENTIAL in levels:
            confidential_seen[c.session_id] = True


@pytest.mark.parametrize("seed", range(12))
def test_no_forbidden_action_executes_under_compromised_agent(seed):
    rng = random.Random(seed)
    clock = FakeClock()
    env = SandboxEnv.default()
    gw = Gateway(env, Policy.load(), ApprovalService(TEST_SECRET, clock, ttl_seconds=30),
                 AuditLog(), clock)
    sessions: dict[str, SessionState] = {}
    tokens: list[tuple[str, dict, str]] = []  # (session_id, raw call, token)
    stats = {s: 0 for s in Status}
    abuse = {"swap": 0, "replay": 0, "cross_session": 0}

    for i in range(150):
        s = SessionState(f"s{seed}-{i}", random_grant(rng, clock.now()))
        sessions[s.session_id] = s
        for _ in range(rng.randint(3, 12)):
            clock.advance(rng.choice([0, 1, 5, 20]))
            roll = rng.random()
            if tokens and roll < 0.25:
                sid, raw, tok = rng.choice(tokens)
                kind = rng.choice(["swap", "replay", "cross_session"])
                abuse[kind] += 1
                target = s if kind == "cross_session" else sessions[sid]
                raw2 = mutate_call(rng, raw) if kind == "swap" else raw
                r = gw.submit(raw2, target, risk=random_risk(rng), approval_token=tok)
            else:
                raw = random_call(rng, s.grant)
                r = gw.submit(raw, s, risk=random_risk(rng))
                if r.status is Status.PENDING_APPROVAL:
                    stats[Status.PENDING_APPROVAL] += 1
                    token = gw.approvals.approve(r.approval_request_id)  # rubber-stamp human
                    tokens.append((s.session_id, raw, token))
                    if rng.random() < 0.6:
                        r = gw.submit(raw, s, risk=random_risk(rng), approval_token=token)
            stats[r.status] += 1

    check_postconditions(gw, env, sessions, None)
    assert gw.audit.verify().ok

    # Guard against a vacuous test: the generator must exercise every path.
    assert stats[Status.EXECUTED] > 20 and stats[Status.DENIED] > 50
    assert stats[Status.PENDING_APPROVAL] > 5
    assert any(rec.call.tool == "send_email" for rec in gw.trace)
    assert all(v > 0 for v in abuse.values())
    print(f"seed={seed} stats={ {k.value: v for k, v in stats.items()} } abuse={abuse} "
          f"sends={len(env.outbox)}")


def test_risk_score_is_monotonic_and_cannot_unlock_denials():
    """For many random calls, verdict severity never decreases as risk rises,
    and a DENY under any risk value is a DENY under every risk value."""
    from aegis.core.policy import evaluate
    from aegis.core.schemas import ValidatedCall
    from aegis.tools.registry import TOOLS
    from aegis.tools.validation import ValidationError, parse_envelope, validate_args

    rng = random.Random(1234)
    policy, env, checked = Policy.load(), SandboxEnv.default(), 0
    for _ in range(3000):
        s = SessionState("mono", random_grant(rng, 1_800_000_000.0))
        try:
            tool, raw_args = parse_envelope(random_call(rng, s.grant))
            if tool not in TOOLS:
                continue
            vc = ValidatedCall.create("mono", tool, validate_args(tool, raw_args, TOOLS[tool].args))
        except ValidationError:
            continue
        verdicts = [evaluate(vc, s, policy, env, RiskReport(x), 1_800_000_000.0).verdict
                    for x in (0.0, 0.25, 0.49, 0.5, 0.75, 1.0)]
        assert verdicts == sorted(verdicts)
        none_v = evaluate(vc, s, policy, env, None, 1_800_000_000.0).verdict
        if any(v.name == "DENY" for v in verdicts + [none_v]):
            assert all(v.name == "DENY" for v in verdicts + [none_v])
        checked += 1
    assert checked > 1000
