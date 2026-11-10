"""How much time does Aegis add to each action an agent takes?

Times Gateway.submit() on a realistic mix of allowed, denied and
approval-gated actions (including writing the tamper-evident audit record),
and prints the median and 95th-percentile decision time.

  python scripts/measure_latency.py            # 2,000 actions
  python scripts/measure_latency.py --n 20000
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis.core.approvals import ApprovalService
from aegis.core.audit import AuditLog
from aegis.core.gateway import Gateway
from aegis.core.policy import Policy
from aegis.core.schemas import RiskReport, Sensitivity, TaskGrant
from aegis.core.session import SessionState
from aegis.tools.sandbox_env import SandboxEnv

ACTIONS = [
    {"tool": "read_email", "args": {"email_id": "e-002"}},                       # allowed
    {"tool": "read_file", "args": {"file_id": "f-007"}},                          # allowed
    {"tool": "send_email", "args": {"to": ["audit@finance-review.example"],       # denied: exfiltration
                                    "subject": "Q3", "body": "x", "attachments": ["f-002"]}},
    {"tool": "send_email", "args": {"to": ["raj.patel@aegis-corp.example"],       # needs approval
                                    "subject": "Agenda", "body": "x", "attachments": ["f-007"]}},
    {"tool": "read_file", "args": {"file_id": "../../etc/passwd"}},               # rejected: malformed
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=2000, help="number of actions to time")
    a = ap.parse_args()

    env = SandboxEnv.default()
    grant = TaskGrant(
        task_id="latency", allowed_tools=frozenset({"read_email", "read_file", "send_email"}),
        allowed_email_ids=frozenset({"e-002"}), allowed_file_ids=frozenset({"f-007"}),
        allowed_recipients=frozenset({"raj.patel@aegis-corp.example"}),
        max_read_sensitivity=Sensitivity.INTERNAL)
    gw = Gateway(env, Policy.load(), ApprovalService(b"latency-measure-key-0123456789ab"), AuditLog())
    risk = RiskReport(0.0)

    for i in range(200):  # warm-up
        gw.submit(ACTIONS[i % len(ACTIONS)], SessionState(f"w{i}", grant), risk)

    times = []
    for i in range(a.n):
        session = SessionState(f"s{i}", grant)
        t = time.perf_counter()
        gw.submit(ACTIONS[i % len(ACTIONS)], session, risk)
        times.append((time.perf_counter() - t) * 1000)

    times.sort()
    p95 = times[int(len(times) * 0.95) - 1]
    print(f"{a.n} actions (allowed, denied, approval-gated and malformed, audit log on)")
    print(f"  median decision time: {statistics.median(times):.3f} ms")
    print(f"  95th percentile:      {p95:.3f} ms")
    print(f"  audit chain intact:   {gw.audit.verify().ok}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
