from __future__ import annotations

import pytest

from aegis.core.approvals import ApprovalService
from aegis.core.audit import AuditLog
from aegis.core.clock import FakeClock
from aegis.core.gateway import Gateway
from aegis.core.policy import Policy
from aegis.core.schemas import RiskReport, Sensitivity, TaskGrant
from aegis.core.session import SessionState
from aegis.tools.sandbox_env import SandboxEnv

TEST_SECRET = bytes(range(32))
SAFE = RiskReport(score=0.0, detector="test-says-safe")
INTERNAL_USER = "priya.sharma@aegis-corp.example"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def env() -> SandboxEnv:
    return SandboxEnv.default()


@pytest.fixture
def policy() -> Policy:
    return Policy.load()


@pytest.fixture
def gateway(env, policy, clock) -> Gateway:
    return Gateway(
        env=env,
        policy=policy,
        approvals=ApprovalService(TEST_SECRET, clock=clock, ttl_seconds=300),
        audit=AuditLog(),
        clock=clock,
    )


def make_grant(
    tools=("read_email", "search_files", "read_file", "draft_email", "send_email"),
    emails=("e-001", "e-002", "e-003", "e-004", "e-005", "e-006", "e-007", "e-008"),
    files=("f-001", "f-002", "f-003", "f-004", "f-005", "f-006", "f-007", "f-008"),
    recipients=(),
    max_read=Sensitivity.CONFIDENTIAL,
    expires_at=None,
    task_id="test_task",
) -> TaskGrant:
    return TaskGrant(
        task_id=task_id,
        allowed_tools=frozenset(tools),
        allowed_email_ids=frozenset(emails),
        allowed_file_ids=frozenset(files),
        allowed_recipients=frozenset(recipients),
        max_read_sensitivity=max_read,
        expires_at=expires_at,
    )


def session(grant: TaskGrant | None = None, sid: str = "s-test") -> SessionState:
    return SessionState(sid, grant or make_grant())


def send(to, body="Hello", subject="Hi", attachments=()):
    return {
        "tool": "send_email",
        "args": {"to": list(to), "subject": subject, "body": body, "attachments": list(attachments)},
    }


def call(tool: str, **args):
    return {"tool": tool, "args": args}
