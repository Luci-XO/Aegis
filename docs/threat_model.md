# Threat model (v0.1)

## System
An AI assistant reads emails and files and may draft or send email. Every tool
call goes through the Aegis gateway. All tools are simulated; nothing leaves
the process.

## Assets
- Confidential synthetic files (payroll, customer list, credentials, contract).
- The ability to send email on the user's behalf.
- Integrity of the audit log.

## Trust levels
| Source | Trust |
|---|---|
| Application code, policy file, tool registry | Trusted |
| The user's task selection, which produces the `TaskGrant` | Trusted |
| The human approver, using the approval UI | Trusted (but may make mistakes) |
| Email bodies and subjects, file contents, web pages, tool outputs | **Untrusted** |
| Email sender address (mail-system metadata) | Trusted in this simulation only; real headers can be spoofed |
| Agent plans, tool-call requests, agent claims about results | **Untrusted** |
| Detector risk scores | Advisory only, never an authorization |

## Attacker
Controls the text of some emails or documents the agent reads. May write
instructions, paraphrases, look-alike domains and multi-step plans. We assume
the attacker can **fully control the agent's proposed tool calls** (the
"compromised planner" assumption). The attacker cannot modify code, policy,
grants or the approval UI, and cannot read the approval secret.

## Security goals (enforced and tested)
1. A tool runs only if it is registered, enabled, in the task grant, and the grant is unexpired.
2. A call only touches emails and files that exist, are in the grant, and are within its sensitivity clearance.
3. Email is only sent to recipients in the grant.
4. Once confidential data has been returned to the agent in a session, or is attached, it cannot be sent outside the organisation (no override, not even with approval).
5. Every send needs a human approval bound to the exact session, tool and arguments. Approvals are single-use and expire.
6. A detector score can raise a verdict but never lower one.
7. Any validation error, policy-engine error or audit-write failure means the action does not run.
8. The agent is told truthfully when an action was blocked.
9. Audit records contain no message bodies, file contents or full addresses.

## Out of scope (known gaps)
- **In-scope abuse:** if the user grants "send to Raj", an injection can still change *what* is said to Raj, and internal data can still go to Raj after approval. The human approver sees the full message and is the control here.
- **Approver error:** a human who approves a harmful action shown to them. The approval display is rendered from the real arguments to make this harder, not impossible.
- **Grant derivation:** in the MVP, grants come from task templates. Deriving grants from free-text requests is not yet implemented.
- **Coarse labels:** the session high-water mark over-restricts. After reading any confidential file, all external email in that session is blocked.
- **Side channels** (timing, the number of tool calls), covert encoding inside allowed messages to allowed recipients.
- Compromised host, stolen approval secret, or someone deleting the whole audit log. The hash chain makes edits detectable, not impossible. Tail truncation needs an external anchor (`AuditLog.head()`).
- Multi-agent and multi-user deployments, real accounts, real network calls.
