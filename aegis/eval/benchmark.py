"""Benchmark driver.

Configurations (same cases, tools, agent and success checks):

  A_unprotected    no policy, no detector, full user permissions
  B_detector_only  A + block sends when the detector flags input (or fails)
  C_gateway_only   policy gateway + approvals, no detector
  D_aegis          policy gateway + approvals + detector
  C2 / D2          ablation: same, but sends are not approval-gated unless the
                   egress table (or, in D2, the detector) requires it

The oracle always scores against the frozen default policy, so
"unauthorized" and "unapproved" mean the same thing in every row.

C and D run with two simulated approvers: "intent" (checks recipients and
attachments against the task) and "rubber_stamp" (approves everything, the
worst case). A and B never ask for approval, so the approver is "n/a".

Usage:
  python -m aegis.eval                      # dev and heldout, scripted agent
  python -m aegis.eval --split heldout --report docs/benchmark_results.md
  python -m aegis.eval --agent llm --trials 3
"""

from __future__ import annotations

import hashlib
import json
import platform
import secrets
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from aegis.agent.approvers import Approver, IntentApprover, RubberStampApprover
from aegis.agent.base import Agent
from aegis.agent.scenarios import ExecutorKind, Scenario, build_stack, load_scenarios
from aegis.agent.scripted import ScriptedAgent
from aegis.core.clock import FakeClock
from aegis.core.policy import Policy
from aegis.detect.base import SafeDetector
from aegis.detect.rules import RuleDetector
from aegis.eval import goals
from aegis.eval.baselines import full_access_grant
from aegis.eval.detector_eval import documents_for, evaluate_detector
from aegis.eval.metrics import CaseResult, summarize
from aegis.eval.oracle import audit_run

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Config:
    name: str
    executor: ExecutorKind
    use_detector: bool
    detector_escalation: bool  # does the policy escalate when there is no detector result?
    approvers: tuple[str, ...]
    send_requires_approval: bool = True  # False = "low friction" ablation policy


CONFIGS: dict[str, Config] = {
    "A_unprotected": Config("A_unprotected", "unprotected", False, False, ("n/a",)),
    "B_detector_only": Config("B_detector_only", "detector_only", True, False, ("n/a",)),
    "C_gateway_only": Config("C_gateway_only", "gateway", False, False, ("intent", "rubber_stamp")),
    "D_aegis": Config("D_aegis", "gateway", True, True, ("intent", "rubber_stamp")),
    # Ablation: sends are not approval-gated by default; only the egress table
    # and (in D2) the detector can require approval. Isolates the detector's value.
    "C2_gateway_low_friction": Config("C2_gateway_low_friction", "gateway", False, False,
                                      ("intent", "rubber_stamp"), send_requires_approval=False),
    "D2_aegis_low_friction": Config("D2_aegis_low_friction", "gateway", True, True,
                                    ("intent", "rubber_stamp"), send_requires_approval=False),
}

APPROVERS: dict[str, Callable[[], Approver]] = {
    "intent": IntentApprover, "rubber_stamp": RubberStampApprover, "n/a": IntentApprover,
}


def policy_variant(base: Policy, cfg: Config) -> Policy:
    """Derive a configuration's policy from the frozen default policy.

    Only two switches change; the egress table, grants and every deny rule
    stay identical across configurations.
    """
    from dataclasses import replace

    from aegis.core.policy import ToolPolicy

    policy, tags = base, []
    if cfg.detector_escalation != base.escalate_when_detector_unavailable:
        policy = replace(policy, escalate_when_detector_unavailable=cfg.detector_escalation)
        tags.append("no-detector-escalation")
    if not cfg.send_requires_approval:
        tools = dict(policy.tools)
        tools["send_email"] = ToolPolicy(enabled=tools["send_email"].enabled, require_approval=False)
        policy = replace(policy, tools=tools)
        tags.append("low-friction")
    if tags:
        policy = replace(policy, version=f"{base.version}+{'+'.join(tags)}")
    return policy


AgentFactory = Callable[[Scenario], Agent]


def scripted_factory(sc: Scenario) -> Agent:
    return ScriptedAgent(sc.injections or None)


def run_case(
    sc: Scenario, cfg: Config, approver_name: str, agent: Agent, trial: int,
    policy: Policy, detector: SafeDetector, secret: bytes,
    capture: list[Any] | None = None,
) -> CaseResult:
    """Run one case. If `capture` is a list, the RunResult (with every step) is appended to it."""
    clock = FakeClock()
    stack = build_stack(
        sc, APPROVERS[approver_name](), detector if cfg.use_detector else None, secret,
        policy=policy_variant(policy, cfg), clock=clock,
        executor_kind=cfg.executor, detector_threshold=policy.escalation_threshold,
    )
    res = stack.runner.run(agent, stack.task, session_id=f"{sc.id}-t{trial}", case_id=sc.id)
    if capture is not None:
        capture.append((res, stack))
    ctx = goals.GoalContext(env=stack.env, steps=res.steps)
    user_goal = sc.user_goal or goals.default_user_goal(stack.task, stack.initial_env)
    tool_grant = stack.task.grant if cfg.executor == "gateway" else full_access_grant(stack.initial_env)
    oracle = audit_run(res.steps, stack.task.grant, tool_grant, stack.initial_env, policy, clock.now())
    return CaseResult(
        config=cfg.name, approver=approver_name, split=sc.split, case_id=sc.id, trial=trial,
        label=sc.label, category=sc.category,
        attacker_goal_met=None if sc.attacker_goal is None else goals.check(sc.attacker_goal, ctx),
        user_goal_met=goals.check(user_goal, ctx),
        forbidden_proposed=oracle.forbidden_proposed,
        unauthorized_executions=oracle.unauthorized_executions,
        unapproved_side_effects=oracle.unapproved_side_effects,
        blocked_steps=sum(s.status in ("denied", "failed", "rejected_by_user") for s in res.steps),
        approvals_requested=sum(s.approval is not None for s in res.steps),
        approvals_rejected=sum(s.approval == "rejected" for s in res.steps),
        n_steps=len(res.steps), stop_reason=res.stop_reason, wall_ms=round(res.wall_ms, 4),
        step_ms=tuple(round(s.gateway_ms, 4) for s in res.steps),
        step_statuses=tuple(s.status for s in res.steps),
        step_rules=tuple(s.rule_ids for s in res.steps),
    )


def text_sha256(path: Path) -> str:
    """SHA-256 of a text file with line endings normalised to LF.

    Git on Windows checks files out with CRLF by default, which changes the
    raw bytes but not the content. Normalising keeps hashes identical across
    operating systems."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


_sha256 = text_sha256


def _git_commit() -> str | None:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,  # noqa: S607
                             text=True, timeout=5, check=False)
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True,  # noqa: S607
                               text=True, timeout=5, check=False)
        if out.returncode != 0:
            return None
        return out.stdout.strip() + ("-dirty" if dirty.stdout.strip() else "")
    except (OSError, subprocess.SubprocessError):
        return None


def provenance(splits: Sequence[str], agent_meta: dict[str, Any], trials: int, policy: Policy) -> dict[str, Any]:
    pkg = Path(str(resources.files("aegis")))
    return {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": _git_commit(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "agent": agent_meta,
        "trials": trials,
        "policy_version": policy.version,
        "escalation_threshold": policy.escalation_threshold,
        "hashes": {
            "policy": _sha256(pkg / "policies" / "default.json"),
            "policy_engine": _sha256(pkg / "core" / "policy.py"),
            "detector": _sha256(pkg / "detect" / "rules.py"),
            **{f"dataset_{s}": _sha256(pkg / "data" / "scenarios" / f"{s}.json") for s in splits},
        },
        "dataset_versions": {s: load_scenarios(s)[0] for s in splits},
        "detector": RuleDetector.name,
    }


@dataclass
class BenchmarkResult:
    metadata: dict[str, Any]
    cases: list[CaseResult] = field(default_factory=list)
    summaries: list[dict[str, Any]] = field(default_factory=list)
    detector: dict[str, Any] = field(default_factory=dict)


def run_benchmark(
    splits: Sequence[str] = ("dev", "heldout"),
    trials: int = 1,
    agent_factory: AgentFactory = scripted_factory,
    configs: Sequence[str] = tuple(CONFIGS),
) -> BenchmarkResult:
    policy = Policy.load()
    detector = SafeDetector(RuleDetector())
    secret = secrets.token_bytes(32)
    loaded = {s: load_scenarios(s)[1] for s in splits}
    sample_agent = agent_factory(next(iter(loaded.values()))[0])
    out = BenchmarkResult(metadata=provenance(splits, sample_agent.metadata(), trials, policy))
    for split, scenarios in loaded.items():
        for name in configs:
            cfg = CONFIGS[name]
            for approver in cfg.approvers:
                group = [
                    run_case(sc, cfg, approver, agent_factory(sc), t, policy, detector, secret)
                    for sc in scenarios for t in range(trials)
                ]
                out.cases += group
                out.summaries.append({"split": split, "config": name, "approver": approver,
                                      **summarize(group)})
        docs = documents_for(split, scenarios)
        out.detector[split] = evaluate_detector(docs, detector, policy.escalation_threshold)
    return out


# ---------------------------------------------------------------- storage

_SCHEMA = """
CREATE TABLE IF NOT EXISTS benchmark_runs (run_id TEXT PRIMARY KEY, created_at TEXT, metadata TEXT);
CREATE TABLE IF NOT EXISTS case_results (run_id TEXT, config TEXT, approver TEXT, split TEXT,
    case_id TEXT, trial INTEGER, label TEXT, category TEXT, attacker_goal_met INTEGER,
    user_goal_met INTEGER, unauthorized_executions INTEGER, detail TEXT);
CREATE TABLE IF NOT EXISTS summaries (run_id TEXT, split TEXT, config TEXT, approver TEXT, metrics TEXT);
CREATE TABLE IF NOT EXISTS detector_results (run_id TEXT, split TEXT, metrics TEXT);
"""


def save(result: BenchmarkResult, out_dir: Path) -> str:
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(3)
    con = sqlite3.connect(out_dir / "benchmark.sqlite")
    try:
        con.executescript(_SCHEMA)
        con.execute("INSERT INTO benchmark_runs VALUES (?, ?, ?)",
                    (run_id, result.metadata["created_at"], json.dumps(result.metadata)))
        con.executemany(
            "INSERT INTO case_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(run_id, c.config, c.approver, c.split, c.case_id, c.trial, c.label, c.category,
              None if c.attacker_goal_met is None else int(c.attacker_goal_met), int(c.user_goal_met),
              c.unauthorized_executions, json.dumps(c.to_dict())) for c in result.cases])
        con.executemany("INSERT INTO summaries VALUES (?, ?, ?, ?, ?)",
                        [(run_id, s["split"], s["config"], s["approver"], json.dumps(s))
                         for s in result.summaries])
        con.executemany("INSERT INTO detector_results VALUES (?, ?, ?)",
                        [(run_id, k, json.dumps(v)) for k, v in result.detector.items()])
        con.commit()
    finally:
        con.close()
    (out_dir / f"{run_id}.json").write_text(json.dumps({
        "run_id": run_id, "metadata": result.metadata, "summaries": result.summaries,
        "detector": result.detector, "cases": [c.to_dict() for c in result.cases]}, indent=2), "utf-8")
    return run_id


# ---------------------------------------------------------------- report

def _fmt(r: dict[str, Any]) -> str:
    if r["rate"] is None:
        return "n/a"
    lo, hi = r["ci95"]
    return f"{r['rate'] * 100:.0f}% ({r['k']}/{r['n']}, CI {lo * 100:.0f}-{hi * 100:.0f})"


def render_markdown(result: BenchmarkResult, run_id: str) -> str:
    m = result.metadata
    lines = [
        f"# Benchmark results: run `{run_id}`",
        "",
        "Generated by `python -m aegis.eval`. Do not edit by hand.",
        "",
        f"- Commit: `{m['git_commit']}`, Python {m['python']}, agent `{m['agent'].get('agent')}`, "
        f"trials per case: {m['trials']}",
        f"- Policy `{m['policy_version']}`, escalation threshold {m['escalation_threshold']}, "
        f"detector `{m['detector']}`",
        f"- Datasets: {', '.join(f'{k} `{v}`' for k, v in m['dataset_versions'].items())}",
        "- Rates show the 95% Wilson interval. Definitions: `aegis/eval/metrics.py`.",
        "",
    ]
    for split in sorted({s["split"] for s in result.summaries}, key=lambda x: (x != "heldout", x)):
        rows = [s for s in result.summaries if s["split"] == split]
        lines += [
            f"## Split: {split} ({rows[0]['attack_runs']} attack runs, {rows[0]['benign_runs']} benign runs per row)",
            "",
            "| Config | Approver | Attack success | Blocking rate | Unauthorized execs | "
            "Unapproved side effects | Utility (benign) | False positives (benign) | "
            "Utility under attack | Approvals/run | Step ms median / p95 |",
            "|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for s in rows:
            lines.append(
                f"| {s['config']} | {s['approver']} | {_fmt(s['attack_success_rate'])} | "
                f"{_fmt(s['blocking_rate'])} | {s['unauthorized_executions']} | "
                f"{s['unapproved_side_effects']} | {_fmt(s['utility'])} | {_fmt(s['false_positive_rate'])} | "
                f"{_fmt(s['utility_under_attack'])} | {s['approvals_per_run']} | "
                f"{s['step_ms']['median']} / {s['step_ms']['p95']} |")
        d = result.detector.get(split)
        if d:
            lines += [
                "",
                f"Detector `{m['detector']}` on {d['documents']} unique documents in this split "
                f"(threshold {d['threshold']}): precision {d['precision']}, recall {d['recall']}, "
                f"F1 {d['f1']}, false-positive rate {d['false_positive_rate']} "
                f"(TP {d['tp']}, FP {d['fp']}, FN {d['fn']}, TN {d['tn']}).",
            ]
        lines += ["", f"### Per-case outcomes ({split})", "",
                  "| Case | Label | Category | " + " | ".join(
                      f"{s['config'].split('_')[0]}{'' if s['approver'] == 'n/a' else '/' + s['approver'][:2]}"
                      for s in rows) + " |",
                  "|---|---|---|" + "---|" * len(rows)]
        ids = list(dict.fromkeys(c.case_id for c in result.cases if c.split == split))
        for cid in ids:
            cells = []
            first = None
            for s in rows:
                cs = [c for c in result.cases if c.split == split and c.case_id == cid
                      and c.config == s["config"] and c.approver == s["approver"]]
                first = first or cs[0]
                n = len(cs)
                suffix = "" if n == 1 else f" {{k}}/{n}"
                if cs[0].label == "attack":
                    hit = sum(bool(c.attacker_goal_met) for c in cs)
                    cell = "**ATTACK OK**" if hit else "blocked"
                    cells.append(cell + suffix.format(k=hit) if hit else cell)
                else:
                    ok = sum(c.user_goal_met for c in cs)
                    cells.append("done" if ok == n else "**FAILED**" + suffix.format(k=n - ok))
            if first is None:
                continue
            lines.append(f"| {cid} | {first.label} | {first.category} | " + " | ".join(cells) + " |")
        lines.append("")
    lines += ["Legend: for attack cases, **ATTACK OK** means the attacker's goal was reached in the final "
              "environment; `blocked` means it was not. For benign cases, `done` means the user's goal was "
              "reached. Column letters: A, B, C, D, C2, D2 configurations; `/in` intent approver, "
              "`/ru` rubber-stamp. In C2/D2, ordinary sends run without approval by design, so the oracle "
              "(which scores against the default policy) counts them as unapproved side effects."]
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="python -m aegis.eval")
    ap.add_argument("--split", choices=["dev", "heldout", "all"], default="all")
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--agent", choices=["scripted", "llm"], default="scripted")
    ap.add_argument("--out", default="results")
    ap.add_argument("--report", help="also write the markdown report to this path")
    a = ap.parse_args(argv)
    if a.trials < 1:
        ap.error("--trials must be >= 1")

    factory: AgentFactory = scripted_factory
    if a.agent == "llm":
        from aegis.agent.llm_agent import LLMAgent
        from aegis.agent.llm_client import client_from_env

        client = client_from_env()
        if client is None:
            print("Set AEGIS_LLM_PROVIDER and AEGIS_LLM_MODEL (and a key for hosted APIs).")
            return 2
        factory = lambda sc: LLMAgent(client)  # noqa: E731
    elif a.trials > 1:
        print("note: the scripted agent is deterministic; extra trials repeat identical runs.")

    splits = ("dev", "heldout") if a.split == "all" else (a.split,)
    result = run_benchmark(splits, a.trials, factory)
    run_id = save(result, Path(a.out))
    md = render_markdown(result, run_id)
    (Path(a.out) / f"{run_id}.md").write_text(md, "utf-8")
    if a.report:
        Path(a.report).write_text(md, "utf-8")
    print(md)
    print(f"Saved run {run_id} to {a.out}/ (benchmark.sqlite, {run_id}.json, {run_id}.md)")
    return 0
