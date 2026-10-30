# Aegis

Security and policy enforcement for AI agents.

Aegis puts a deterministic policy gateway between an AI agent and its tools.
The agent may propose any action, but each one is checked against explicit
rules (which tools, which resources, which recipients, which data may flow
where, whether a human must approve) **before** it executes. The LLM is never
the final authority, and a threat detector can only make decisions stricter.

> Status: **Stage 4, agent and detector.** Security core (gateway, policy,
> approvals, audit), task templates, a rule-based detector, scripted and LLM
> agents, and the run loop are done. The benchmark and dashboard come next.
> All data is synthetic and all tools are simulated.

## Quick start

Requires Python 3.11+. The security core has **no third-party dependencies**,
so it runs without an install step:

```bash
git clone https://github.com/Luci-XO/Aegis.git
cd Aegis
python -m pip install pytest      # only needed to run tests
python -m pytest                   # run the test suite
python scripts/demo_core.py        # CLI walkthrough of an attack being blocked
python scripts/run_scenarios.py    # hijacked agent + detector + approver on 10 dev scenarios
python scripts/mutation_check.py   # inject 23 security bugs, confirm tests catch them
```

To try a real model later, set `AEGIS_LLM_PROVIDER`, `AEGIS_LLM_MODEL` and
(for hosted APIs) `AEGIS_LLM_API_KEY`, then run
`python scripts/run_scenarios.py --agent llm`. A local
[Ollama](https://ollama.com) server works without a key
(`AEGIS_LLM_PROVIDER=ollama`).

Optional editable install: `python -m pip install -e ".[dev]"`.

## What the demo shows

`scripts/demo_core.py` plays a fully compromised agent that obeys a hidden
instruction in an invoice email, while the detector is stubbed to report
**risk 0.0 (safe)**:

```
> Compromised agent obeys: send payroll f-002 to audit@finance-review.example
  status : denied
  P007   : recipient domain 'finance-review.example' is not granted for this task
  P008   : confidential data to external recipient: deny
  P010   : policy requires approval for 'send_email'

> Agent swaps in the payroll attachment under the same approval
  status : denied
  A008   : The submitted action differs from the approved action; the approval is revoked.
```

## Repository layout

```
aegis/
  core/        schemas, policy engine, gateway, approvals, audit log, rule catalogue
  tools/       argument validation, simulated tools, in-memory sandbox
  detect/      rule-based detector, fail-safe wrapper, risk aggregation
  agent/       task templates, scripted + LLM agents, approvers, runner, scenarios
  policies/    default.json (the policy file)
  data/        synthetic emails/files and dev scenarios (fictional, .example domains)
tests/         core, detector, tasks, runner, LLM agent (fake client), invariants
scripts/       demo_core.py, run_scenarios.py, mutation_check.py
docs/          threat_model.md, architecture.md, agent_and_detector.md
```

## What is tested

- **Core invariant (randomised):** 12 seeds × 150 sessions of a compromised
  agent sending random, malformed and hostile calls with random risk scores,
  plus parameter swaps, replays and cross-session reuse of approval tokens,
  with a human who approves everything. Postconditions are checked against the
  sandbox outbox and the execution trace, written independently of the policy code.
- **Risk monotonicity:** across ~3,000 random calls, a higher risk score never
  lowers a verdict, and a denial holds at every score.
- Targeted tests for schema rejection (path traversal, homoglyphs, header
  injection), each policy rule, approval binding, fail-closed paths, audit
  tamper detection, and audit redaction.
- **End-to-end runs:** five attack scenarios × four detector conditions
  (rules, always-safe, crashing, none) × two approvers (careful, rubber-stamp):
  no attacker destination receives anything. Benign tasks complete.
- **Mutation check:** `scripts/mutation_check.py` injects 23 deliberate
  security bugs. The full suite catches all 23.

## Guarantees and limits

See [docs/threat_model.md](docs/threat_model.md). In short, Aegis does not
stop an injection from changing the wording of a message the user authorised,
does not protect against an approver who approves a harmful action shown to
them, and uses a coarse session label that over-blocks after confidential reads.
The audit hash chain makes edits detectable but does not prevent deletion of
the whole log.

## Prior work

This builds on established ideas rather than claiming a new defense:
tool-level privilege policies ([Progent](https://arxiv.org/abs/2504.11703)),
control/data separation ([CaMeL](https://arxiv.org/abs/2503.18813)),
[design patterns for securing LLM agents](https://arxiv.org/abs/2506.08837), and
the evaluation approach of [AgentDojo](https://arxiv.org/abs/2406.13352). It maps to
OWASP LLM01 (Prompt Injection) and LLM06 (Excessive Agency) in the
[OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).

## License

MIT. See [LICENSE](LICENSE).
