# Aegis

Security and policy enforcement for AI agents.

Aegis puts a deterministic policy gateway between an AI agent and its tools.
The agent may propose any action, but each one is checked against explicit
rules (which tools, which resources, which recipients, which data may flow
where, whether a human must approve) **before** it executes. The LLM is never
the final authority, and a threat detector can only make decisions stricter.

> Status: **complete prototype.** Security core, agent, rule detector, four-way
> benchmark with a held-out split, browser dashboard, technical report and demo
> script are all in place. All data is synthetic and all tools are simulated;
> the whole project has **no third-party runtime dependencies** (only `pytest`
> to run the tests), and reproduces from a clean clone with no install step.

## See it

Run `python -m aegis.web` and open http://127.0.0.1:8000. The dashboard explains
the problem in plain language, then runs real attacks side by side, with and
without Aegis.

![Overview](docs/images/overview.png)

**A hidden instruction in an email.** Without protection, the payroll file leaks.
With Aegis, the same fooled AI tries the same action, and the checkpoint shows
exactly which rules refused it:

![Hidden instruction demo](docs/images/demo-hidden-instruction.png)

**Test your own email.** Upload an `.eml` file (or paste text) and Aegis runs it
with and without protection. Sample files are in [examples/emails](examples/emails).

![Upload your own email](docs/images/upload-your-own-email.png)

**Real AI arena.** Attack a real model (Gemini, OpenAI or local) with poisoned
emails: `python scripts/run_real_ai_benchmark.py`. The dashboard shows how often
the AI was fooled and what Aegis prevented, one tile per email, plus a live
attack button. See [docs/real_ai.md](docs/real_ai.md).

**Results on attacks written after the rules were frozen:**

![Results](docs/images/results.png)

## Quick start

Requires Python 3.10+ (tested on 3.10, 3.11, 3.12, 3.13 and 3.14). The security core has **no third-party dependencies**,
so it runs without an install step:

```bash
git clone https://github.com/Luci-XO/Aegis.git
cd Aegis
python -m pip install pytest      # only needed to run tests
python -m pytest                   # run the test suite
python scripts/demo_core.py        # CLI walkthrough of an attack being blocked
python scripts/run_scenarios.py    # hijacked agent + detector + approver on dev scenarios
python -m aegis.eval               # four-way benchmark on dev + held-out splits
python -m aegis.web                # dashboard at http://127.0.0.1:8000
python scripts/mutation_check.py   # inject 26 security bugs, confirm tests catch them
python scripts/eval_email_classifier.py   # phishing/spam classifier on the 100-email corpus
```

Optional extras: `pip install scikit-learn` for the scikit-learn classifier
backend, and a Gemini key in `.env` for real-model runs. See
[docs/email_classifier.md](docs/email_classifier.md).

To try a real model later, set `AEGIS_LLM_PROVIDER`, `AEGIS_LLM_MODEL` and
(for hosted APIs) `AEGIS_LLM_API_KEY`, then run
`python scripts/run_scenarios.py --agent llm`. A local
[Ollama](https://ollama.com) server works without a key
(`AEGIS_LLM_PROVIDER=ollama`).

Optional editable install: `python -m pip install -e ".[dev]"`.

### Troubleshooting

| Problem | Fix |
|---|---|
| `python` not found, or it is Python 2 | Use `python3` on macOS/Linux, or `py -3` on Windows. |
| Errors as soon as anything starts | Check `python --version`; Python 3.10 or newer is required. |
| `No module named pytest` | Only the tests need it: `python -m pip install pytest`. The demos, benchmark and dashboard run without it. |
| `No module named aegis` | Run commands from the repository root (the folder that contains `aegis/`). |
| Dashboard: `Address already in use` | Pick another port: `python -m aegis.web --port 8080`. |
| Dashboard opens but shows nothing | Use `http://127.0.0.1:8000`, not the file path; the page needs the server. |
| Want the dashboard on another device | `python -m aegis.web --host 0.0.0.0` (demo server; use only on a trusted network). |
| `AEGIS_APPROVAL_SECRET not set` warning | Harmless. A random key is used per run. To silence it, set the variable as shown in `.env.example`. |

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
  eval/        baselines, goal predicates, policy oracle, metrics, benchmark driver
  web/         stdlib HTTP server, interactive session driver, static frontend
  policies/    default.json (the policy file)
  data/        synthetic emails/files, dev + held-out scenarios (fictional, .example)
tests/         core, detector, tasks, runner, LLM agent, benchmark, web, freeze, invariants
scripts/       demo_core.py, run_scenarios.py, demo_dashboard_flow.py, mutation_check.py
docs/          threat_model, architecture, agent_and_detector, benchmark*, dashboard
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
- **Benchmark invariant:** across both splits and every gateway configuration
  (C, D, C2, D2) and approver, a test asserts **0** unauthorized executions,
  while the unprotected baseline executes many. Every attack is verified live
  against the unprotected baseline and every benign task solvable.
- **Mutation check:** `scripts/mutation_check.py` injects 26 deliberate
  security bugs (including three in the benchmark oracle and baselines). The
  full suite catches all 26.

## Benchmark results (held-out split, fully hijacked agent)

From one run on the sandbox; full report in [docs/benchmark_results.md](docs/benchmark_results.md),
method in [docs/benchmark.md](docs/benchmark.md). 10 attack cases, 5 benign, intent approver.

| Config | Attack success | Unauthorized execs | Benign utility | False positives |
|---|---|---|---|---|
| A unprotected | 100% | 18 | 100% | 0% |
| B detector-only | 70% | 14 | 100% | 0% |
| C gateway-only | **10%** | **0** | 100% | 0% |
| D Aegis (gateway + detector) | **10%** | **0** | 100% | 0% |

The gateway cuts attack success from 100% to 10% with zero unauthorized tool
executions; the remaining 10% is the one in-scope wording-manipulation case,
out of scope by design. Detection alone (B) stops far fewer: the frozen detector
caught 3 of 10 held-out attacks (recall 0.30). C and D match here because the
deterministic gateway, not the detector, does the blocking — the intended
finding. Numbers describe this synthetic suite only.

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

## Documentation

- [docs/report.md](docs/report.md) - technical report: method, results, limitations, contribution
- [docs/threat_model.md](docs/threat_model.md) - threat model and what is out of scope
- [docs/architecture.md](docs/architecture.md) - security-core internals
- [docs/agent_and_detector.md](docs/agent_and_detector.md) - agent, detector, run loop
- [docs/benchmark.md](docs/benchmark.md) - benchmark methodology
- [docs/benchmark_results.md](docs/benchmark_results.md) - generated results snapshot
- [docs/dashboard.md](docs/dashboard.md) - dashboard and HTTP API
- [docs/real_ai.md](docs/real_ai.md) - attacking a real AI (Gemini) and the Real AI arena page
- [docs/email_classifier.md](docs/email_classifier.md) - phishing/spam classifier (optional scikit-learn), Gemini judge, VS Code setup
- [docs/demo_script.md](docs/demo_script.md) - three-minute live demo script

## Contribution, in one paragraph

Aegis is not a new defense. It is a small, dependency-free reference
implementation of action-level policy enforcement for AI agents, built around a
deterministic gateway that the language model cannot overrule. Its value is
engineering and evaluation: a four-way ablation (unprotected, detector-only,
gateway-only, full) under a fully-hijacked agent, scored on the real environment
state by a reference-policy oracle; a methodological freeze that separates the
tuning set from a held-out split; and a result that is honest about its limits,
including the cases where both detection and enforcement do not apply. Prior
work it builds on is cited in [docs/report.md](docs/report.md).

## License

MIT. See [LICENSE](LICENSE).
