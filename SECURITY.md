# Security posture

Aegis is a security project, so we state our posture explicitly rather than
claim perfection. **We do not claim "zero vulnerabilities" — no real system can.**
We claim a clear design boundary, specific hardening, an honest scope, and a
repeatable way to find the next bug.

## What Aegis defends

The threat is **prompt injection**: untrusted content (an email, a document)
contains instructions that try to make an AI agent misuse its tools. We assume
the **LLM can be fully compromised** by such content. Aegis defends the
**actions**, not the model:

- No action outside the user task's allow-list of tools, files and recipients.
- No exfiltration of confidential data outside the organisation.
- No high-impact action (send, pay, change bank details) without a valid,
  matching, single-use human approval.

## Why the design is defensible

- **The security decision contains no AI.** The policy engine is deterministic
  and pure standard library. The ML detector is advisory only: it can escalate
  to "needs human approval" but can **never permit** an action the policy denied.
  A wrong or crashing detector cannot open a hole.
- **Fail-safe.** Any malformed input, any unmet policy condition, or any internal
  error results in *deny*. If the tamper-evident audit log cannot be written, the
  action does not run.
- **Approvals are bound.** An approval is an HMAC over a hash of the exact action
  (tool + arguments + recipient + data), single-use and time-limited. Replaying
  an old approval, or changing a field after approval, invalidates it.
- **Scope cannot be widened by content.** Nothing the agent *reads* can grant it
  tools, files or recipients the user's task did not already allow.

## Hardening in this repo

Core:
- Deterministic policy engine; no third-party runtime dependencies in the core.
- Input validation and allow-lists at every boundary; path-traversal and
  look-alike-character checks on tool arguments and addresses.
- HMAC approval tokens: single-use, expiring, action-bound. Secret from env.
- Tamper-evident, append-only audit log; write-before-execute.

Demo dashboard (`aegis/web`):
- Binds to `127.0.0.1` unless a host is given explicitly.
- Rejects oversized request bodies; validates every field against allow-lists.
- Serves static files only from the bundled directory, with the resolved path
  checked to stay inside it, and only a fixed set of extensions.
- Sends defence-in-depth headers on every response: a strict
  `Content-Security-Policy` (`script-src 'self'`, no inline/third-party scripts),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy:
  no-referrer`, `Cross-Origin-Opener-Policy`, `Permissions-Policy`.
- The frontend only ever writes text via `textContent`, so content from emails,
  files or tool arguments cannot inject markup; the CSP is a second layer.
- Never echoes internal error detail to clients; logs server-side only.
- In-memory session store with a cap and FIFO eviction.

Secrets & data:
- `.env` and `.env.*` are git-ignored; no key is hard-coded or logged.
- All demo data is synthetic and uses the reserved `.example` TLD; tools are
  simulated, so a demonstrated attack cannot touch a real inbox or real money.

## How we look for bugs (repeatable)

- **320+ automated tests**, across Python 3.10–3.14.
- **Mutation testing**: 26 planted security bugs, 26/26 caught by the tests
  (`python scripts/mutation_check.py`).
- **Invariant / fuzz testing**: 13,865 randomised attack attempts executed
  **0** forbidden actions.
- **Methodological freeze**: hashes of the policy, policy engine and detector are
  recorded (`aegis/eval/freeze.json`) before the held-out attack split was
  written; a test fails if they change, so the rules can't be quietly tuned.
- **Static checks**: `ruff` and `mypy` run clean in CI on every push.

## Explicitly out of scope (known limits, not hidden)

- Aegis controls *which actions run and where data goes*, not the *wording* of a
  reply the user already authorised.
- A human who approves a clearly-shown harmful message can still cause harm.
- Results come from a synthetic test set: they demonstrate the design, not a
  guarantee against every possible attack.
- Policies are hand-written today; learning and scaling them is future work.
- The dashboard is a local demonstration tool, not a hardened multi-tenant
  service; it has no user accounts or network auth and is meant to run on
  `localhost`.

## Reporting

Please report security issues privately to the maintainer rather than in a
public issue. Include the steps to reproduce, the affected version or commit,
and the impact you observed. You can expect an acknowledgement within 3
working days. Please do not include real personal data in any report; use
synthetic examples.
