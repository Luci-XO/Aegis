"""Catalogue of every rule identifier the gateway can emit.

Each audit record and decision references these IDs, so a reviewer can map any
blocked action back to a single documented rule.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    title: str
    description: str


_RULES = [
    # Policy rules
    RuleInfo("P000", "Internal error", "The policy engine failed; the action is denied (fail closed)."),
    RuleInfo("P001", "Unknown or disabled tool", "The tool is not registered or not enabled by policy."),
    RuleInfo("P002", "Invalid request", "The call does not match the tool's argument schema."),
    RuleInfo("P003", "Tool not granted", "The current task grant does not include this tool."),
    RuleInfo("P004", "Grant expired", "The task grant has expired."),
    RuleInfo("P005", "Resource not granted", "The call references an email or file outside the task grant, or one that does not exist."),
    RuleInfo("P006", "Sensitivity above clearance", "The resource is more sensitive than the grant allows."),
    RuleInfo("P007", "Recipient not granted", "A recipient is not in the task grant's recipient list."),
    RuleInfo("P008", "Egress denied", "Data at this sensitivity may not flow to this destination."),
    RuleInfo("P009", "Egress needs approval", "This data flow requires human approval."),
    RuleInfo("P010", "Side effect needs approval", "Policy requires human approval for this tool."),
    RuleInfo("P011", "High-risk input", "The detector flagged the content; side effects need approval."),
    RuleInfo("P012", "Detector unavailable", "No detector result; side effects are escalated."),
    # Approval token failures
    RuleInfo("A001", "Malformed approval token", "The token is not in the expected format."),
    RuleInfo("A002", "Unknown approval request", "No approval request matches the token."),
    RuleInfo("A003", "Bad approval signature", "The token's HMAC does not verify."),
    RuleInfo("A004", "Not approved", "The approval request has not been approved."),
    RuleInfo("A005", "Approval already used", "Approval tokens are single-use; this one was already redeemed."),
    RuleInfo("A006", "Approval expired", "The approval request expired."),
    RuleInfo("A007", "Session mismatch", "The token belongs to a different session."),
    RuleInfo("A008", "Action mismatch", "The submitted action differs from the approved action; the approval is revoked."),
    # Baseline B only (detector-only configuration, used for comparison)
    RuleInfo("B01", "Detector block", "Baseline B: side effect blocked because the detector flagged the input or gave no result."),
    # Gateway runtime
    RuleInfo("G001", "Audit unavailable", "The pre-execution audit record could not be written; the action is not executed."),
    RuleInfo("G002", "Tool execution failed", "The tool raised an error; the action did not complete."),
]

RULES: dict[str, RuleInfo] = {r.rule_id: r for r in _RULES}
