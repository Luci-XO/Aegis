"""Run the development scenarios end to end and print what happened.

Usage:
  python scripts/run_scenarios.py                      # scripted hijacked agent, careful approver
  python scripts/run_scenarios.py --approver rubber_stamp
  python scripts/run_scenarios.py --only dev-04-northwind-detector-miss
  python scripts/run_scenarios.py --agent llm          # needs AEGIS_LLM_* env vars

These are development scenarios. Do not report them as benchmark results.
"""

from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis.agent.approvers import IntentApprover, RejectAllApprover, RubberStampApprover
from aegis.agent.llm_agent import LLMAgent
from aegis.agent.llm_client import client_from_env
from aegis.agent.scenarios import build_stack, load_scenarios
from aegis.agent.scripted import ScriptedAgent
from aegis.detect.base import SafeDetector
from aegis.detect.rules import RuleDetector

APPROVERS = {"intent": IntentApprover, "rubber_stamp": RubberStampApprover, "reject_all": RejectAllApprover}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--approver", choices=sorted(APPROVERS), default="intent")
    ap.add_argument("--agent", choices=["scripted", "llm"], default="scripted")
    ap.add_argument("--no-detector", action="store_true")
    ap.add_argument("--only")
    a = ap.parse_args()

    client = client_from_env() if a.agent == "llm" else None
    if a.agent == "llm" and client is None:
        print("Set AEGIS_LLM_PROVIDER, AEGIS_LLM_MODEL (and key/base URL) to use --agent llm.")
        return 2

    version, scenarios = load_scenarios("dev")
    detector = None if a.no_detector else SafeDetector(RuleDetector())
    secret = secrets.token_bytes(32)
    print(f"scenarios={version} agent={a.agent} approver={a.approver} "
          f"detector={detector.name if detector else 'none'}\n")
    for sc in scenarios:
        if a.only and sc.id != a.only:
            continue
        stack = build_stack(sc, APPROVERS[a.approver](), detector, secret)
        agent = LLMAgent(client) if client else ScriptedAgent(sc.injections)
        res = stack.runner.run(agent, stack.task, session_id=sc.id, case_id=sc.id)
        print(f"=== {sc.id} [{sc.label}] {sc.description}")
        print(res.report())
        scores = [f"{d['tool']}@{d['step']}={d['score']}" for d in res.detections]
        print(f"Detector scores: {', '.join(scores) or 'n/a'}")
        print(f"Outbox: {[(m.to, m.attachments) for m in stack.env.outbox]}")
        print(f"Audit chain ok: {stack.gateway.audit.verify().ok}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
