"""Load development scenarios and build a fresh, isolated stack for each run."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Any

from aegis.agent.approvers import Approver
from aegis.agent.runner import Runner
from aegis.agent.tasks import TaskInstance, make_task
from aegis.core.approvals import ApprovalService
from aegis.core.audit import AuditLog
from aegis.core.clock import Clock, SystemClock
from aegis.core.gateway import Gateway
from aegis.core.policy import Policy
from aegis.detect.base import SafeDetector
from aegis.tools.sandbox_env import SandboxEnv


@dataclass(frozen=True)
class Scenario:
    id: str
    label: str
    template: str
    params: dict[str, Any]
    injections: dict[str, list[dict[str, Any]]]
    description: str = ""


def load_scenarios(name: str = "dev") -> tuple[str, list[Scenario]]:
    data = json.loads((resources.files("aegis") / "data" / "scenarios" / f"{name}.json").read_text("utf-8"))
    out = [
        Scenario(
            id=s["id"], label=s["label"], template=s["task"]["template"], params=s["task"]["params"],
            injections=s.get("injections", {}), description=s.get("description", ""),
        )
        for s in data["scenarios"]
    ]
    if len({s.id for s in out}) != len(out):
        raise ValueError("duplicate scenario ids")
    return data["version"], out


@dataclass
class Stack:
    env: SandboxEnv
    gateway: Gateway
    runner: Runner
    task: TaskInstance


def build_stack(
    scenario: Scenario,
    approver: Approver,
    detector: SafeDetector | None,
    secret: bytes,
    policy: Policy | None = None,
    clock: Clock | None = None,
) -> Stack:
    clock = clock or SystemClock()
    env = SandboxEnv.default()
    gateway = Gateway(env, policy or Policy.load(), ApprovalService(secret, clock), AuditLog(), clock)
    task = make_task(scenario.template, scenario.params, env, clock.now())
    return Stack(env, gateway, Runner(gateway, approver, detector), task)
