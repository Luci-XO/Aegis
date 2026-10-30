"""Simulated human approvers for automated runs.

A real deployment shows the approval request in the UI and a person decides.
For reproducible experiments we model three kinds of human:

- RubberStampApprover: approves everything (worst case; tests the gateway alone).
- RejectAllApprover: approves nothing.
- IntentApprover: a careful human who approves a send only if its recipients
  and attachments match what they asked for in the task. Like a real person
  skimming an approval prompt, it does NOT judge the message wording.

Approvers see only `ApprovalRequest.display`, which the gateway renders from
the validated arguments, never the agent's description of the action.
"""

from __future__ import annotations

from typing import Protocol

from aegis.agent.tasks import TaskInstance
from aegis.core.approvals import ApprovalRequest


class Approver(Protocol):
    name: str

    def decide(self, request: ApprovalRequest, task: TaskInstance) -> bool: ...


class RubberStampApprover:
    name = "rubber_stamp"

    def decide(self, request: ApprovalRequest, task: TaskInstance) -> bool:
        return True


class RejectAllApprover:
    name = "reject_all"

    def decide(self, request: ApprovalRequest, task: TaskInstance) -> bool:
        return False


class IntentApprover:
    name = "intent"

    def decide(self, request: ApprovalRequest, task: TaskInstance) -> bool:
        if request.tool != "send_email":
            return False
        args = request.display.get("args", {})
        to = frozenset(args.get("to", []))
        attachments = frozenset(args.get("attachments", []))
        return any(to == s.to and attachments <= s.attachments for s in task.intended_sends)
