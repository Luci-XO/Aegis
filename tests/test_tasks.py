"""Task templates produce minimal grants from trusted parameters only."""

from __future__ import annotations

import pytest

from aegis.agent.tasks import TaskError, make_task
from aegis.core.schemas import Sensitivity
from aegis.tools.sandbox_env import SandboxEnv

NOW = 1_800_000_000.0


@pytest.fixture
def env():
    return SandboxEnv.default()


def test_summarize_grants_reads_only(env):
    t = make_task("summarize_inbox", {}, env, NOW)
    assert t.grant.allowed_tools == {"read_email"}
    assert not t.grant.allowed_recipients and not t.grant.allowed_file_ids
    assert t.grant.expires_at == NOW + 900


def test_reply_grants_only_that_email_and_its_sender(env):
    t = make_task("reply_to_sender", {"email_id": "e-002"}, env, NOW)
    assert t.grant.allowed_email_ids == {"e-002"}
    assert t.grant.allowed_recipients == {"billing@vendor-portal.example"}
    assert not t.grant.allowed_file_ids
    assert "send_email" in t.grant.allowed_tools and "read_file" not in t.grant.allowed_tools


def test_share_file_clearance_matches_chosen_file(env):
    t = make_task("share_file", {"file_id": "f-002", "recipients": ["Maya.Chen@aegis-corp.example"]}, env, NOW)
    assert t.grant.allowed_file_ids == {"f-002"}
    assert t.grant.max_read_sensitivity is Sensitivity.CONFIDENTIAL
    assert t.grant.allowed_recipients == {"maya.chen@aegis-corp.example"}


def test_search_excludes_confidential(env):
    t = make_task("search_and_summarize", {"query": "contract"}, env, NOW)
    assert t.grant.max_read_sensitivity is Sensitivity.INTERNAL


@pytest.mark.parametrize(
    "template, params",
    [
        ("delete_everything", {}),
        ("reply_to_sender", {}),
        ("reply_to_sender", {"email_id": "e-999"}),
        ("reply_to_sender", {"email_id": "../e-001"}),
        ("share_file", {"file_id": "f-001"}),
        ("share_file", {"file_id": "f-001", "recipients": []}),
        ("share_file", {"file_id": "f-001", "recipients": ["not-an-address"]}),
        ("share_file", {"file_id": "f-001", "recipients": "a@b.example"}),
        ("search_and_summarize", {"query": ""}),
    ],
)
def test_invalid_task_parameters_are_rejected(env, template, params):
    with pytest.raises(TaskError):
        make_task(template, params, env, NOW)
