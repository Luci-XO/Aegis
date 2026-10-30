"""Benchmark cases ("scenarios") and per-run stack construction.

File format (`aegis/data/scenarios/<split>.json`):

{
  "version": "...", "split": "dev" | "heldout",
  "scenarios": [{
    "id": "...", "label": "benign" | "attack", "category": "...",
    "description": "...",
    "task": {"template": "...", "params": {...}},
    "env": {"inbox": "extend" | "replace", "emails": [...], "files": [...]},   # optional
    "injections": {"<resource id>": [<tool request>, ...]},                  # attack only
    "attacker_goal": <predicate>,                                            # attack only
    "user_goal": <predicate>                                                 # optional
  }]
}

Predicates are defined in `aegis/eval/goals.py`. Case-specific emails and files
use the same shape as `aegis/data/synthetic/*.json`, including the ground-truth
`malicious` flag used to score the detector.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Literal

from aegis.agent.approvers import Approver
from aegis.agent.runner import Executor, Runner
from aegis.agent.tasks import TaskInstance, make_task
from aegis.core.approvals import ApprovalService
from aegis.core.audit import AuditLog
from aegis.core.clock import Clock, SystemClock
from aegis.core.gateway import Gateway
from aegis.core.policy import Policy
from aegis.detect.base import SafeDetector
from aegis.tools.sandbox_env import SandboxEnv

ExecutorKind = Literal["gateway", "unprotected", "detector_only"]
_LABELS = {"benign", "attack"}


@dataclass(frozen=True)
class Scenario:
    id: str
    label: str
    template: str
    params: dict[str, Any]
    injections: dict[str, list[dict[str, Any]]]
    description: str = ""
    split: str = "dev"
    category: str = "uncategorised"
    env_patch: dict[str, Any] = field(default_factory=dict)
    attacker_goal: dict[str, Any] | None = None
    user_goal: dict[str, Any] | None = None


def _parse(raw: dict[str, Any], split: str) -> Scenario:
    if raw.get("label") not in _LABELS:
        raise ValueError(f"{raw.get('id')}: label must be benign or attack")
    sc = Scenario(
        id=raw["id"], label=raw["label"], template=raw["task"]["template"],
        params=raw["task"].get("params", {}), injections=raw.get("injections", {}),
        description=raw.get("description", ""), split=split,
        category=raw.get("category", "uncategorised"), env_patch=raw.get("env", {}),
        attacker_goal=raw.get("attacker_goal"), user_goal=raw.get("user_goal"),
    )
    if sc.label == "attack" and (not sc.injections or sc.attacker_goal is None):
        raise ValueError(f"{sc.id}: attack cases need injections and an attacker_goal")
    if sc.label == "benign" and (sc.injections or sc.attacker_goal is not None):
        raise ValueError(f"{sc.id}: benign cases cannot have injections or an attacker_goal")
    return sc


def load_file(name: str) -> dict[str, Any]:
    path = resources.files("aegis") / "data" / "scenarios" / f"{name}.json"
    data: dict[str, Any] = json.loads(path.read_text("utf-8"))
    return data


def load_scenarios(name: str = "dev") -> tuple[str, list[Scenario]]:
    data = load_file(name)
    split = data.get("split", name)
    out = [_parse(s, split) for s in data["scenarios"]]
    if len({s.id for s in out}) != len(out):
        raise ValueError("duplicate scenario ids")
    return data["version"], out


def build_env(scenario: Scenario) -> SandboxEnv:
    env = SandboxEnv.default()
    patch = scenario.env_patch
    if not patch:
        return env
    extra = SandboxEnv.from_dicts(patch.get("emails", []), patch.get("files", []))
    if set(extra.files) & set(env.files):
        raise ValueError(f"{scenario.id}: case file ids collide with base files")
    mode = patch.get("inbox", "extend")
    if mode == "replace":
        env.emails = dict(extra.emails)
    elif mode == "extend":
        if set(extra.emails) & set(env.emails):
            raise ValueError(f"{scenario.id}: case email ids collide with base emails")
        env.emails.update(extra.emails)
    else:
        raise ValueError(f"{scenario.id}: env.inbox must be 'extend' or 'replace'")
    env.files.update(extra.files)
    return env


@dataclass
class Stack:
    env: SandboxEnv
    initial_env: SandboxEnv  # untouched copy, used by the policy oracle
    executor: Executor
    runner: Runner
    task: TaskInstance
    clock: Clock
    gateway: Gateway | None = None


def build_stack(
    scenario: Scenario,
    approver: Approver,
    detector: SafeDetector | None,
    secret: bytes,
    policy: Policy | None = None,
    clock: Clock | None = None,
    executor_kind: ExecutorKind = "gateway",
    detector_threshold: float = 0.5,
) -> Stack:
    from aegis.eval.baselines import UnprotectedExecutor  # local import avoids a cycle

    clock = clock or SystemClock()
    env = build_env(scenario)
    initial = env.clone()
    task = make_task(scenario.template, scenario.params, env, clock.now())
    gateway: Gateway | None = None
    executor: Executor
    if executor_kind == "gateway":
        gateway = Gateway(env, policy or Policy.load(), ApprovalService(secret, clock), AuditLog(), clock)
        executor = gateway
    elif executor_kind == "unprotected":
        executor = UnprotectedExecutor(env, clock)
    elif executor_kind == "detector_only":
        executor = UnprotectedExecutor(env, clock, block_side_effects_at=detector_threshold)
    else:
        raise ValueError(f"unknown executor kind '{executor_kind}'")
    return Stack(env, initial, executor, Runner(executor, approver, detector), task, clock, gateway)
