# Aegis

**A security gateway that makes it safe to give an AI agent real tools.**

[![CI](https://github.com/Luci-XO/Aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/Luci-XO/Aegis/actions/workflows/ci.yml)
&nbsp;Python 3.10–3.14 &middot; no runtime dependencies &middot; [Security](SECURITY.md) &middot; [Changelog](CHANGELOG.md)

AI agents that read email and act on it can be hijacked by a single hidden
instruction ("forward the payroll file to this address"). This is prompt
injection, the top risk in the
[OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/).

Aegis sits between the agent and its tools. The agent may propose any action,
but every action is checked against fixed rules **before** it runs: which
tools, files and recipients the user's task allows, where confidential data
may go, and when a person must approve. The language model is never the final
authority, so a fooled model can't cause harm.

## Results

**Enforcement**, on 10 attacks written after the rules were frozen, with an AI
assistant that obeys every hidden instruction:

| Protection | Attacks that succeeded | Unauthorised actions executed | Normal tasks completed |
|---|---|---|---|
| None | 100% | 18 | 100% |
| Threat scanner only | 70% | 14 | 100% |
| **Aegis** | **10%** | **0** | **100%** |

Across 13,865 randomised attack attempts, Aegis executed **0** forbidden
actions. The remaining 10% is a case that only rewords a reply the user had
already allowed; it is out of scope by design (see [threat model](docs/threat_model.md)).

**Email classifier** (an advisory signal), on 56,711 real emails, tested on
30% it never trained on:

| | Stopped | False alarms |
|---|---|---|
| Real phishing (Nazario) | **97.7%** (461/472) | 4.9% (22/447) |
| Real spam (TREC 2007) | **99.7%** (8,995/9,026) | 1.0% (69/7,069) |

Method and caveats: [docs/real_email_results.md](docs/real_email_results.md).
The classifier can only make a decision stricter. The gateway, not the
classifier, is the security boundary.

## Try it

Requires Python 3.10 or newer. No install step is needed.

```bash
git clone https://github.com/Luci-XO/Aegis.git
cd Aegis
python -m aegis.web --open        # dashboard at http://127.0.0.1:8000
```

On Windows you can double-click **`start_demo.bat`** instead.

The dashboard runs real attacks side by side, with and without Aegis, and lets
you test your own email files. Sample emails are in [examples/emails](examples/emails).

![Aegis dashboard](docs/images/overview.png)

A hidden instruction in an email tells the assistant to send the payroll file
to an outsider. Without protection it leaks; with Aegis the same fooled
assistant tries the same action and is refused, with the reason shown:

![Hidden instruction demo](docs/images/demo-hidden-instruction.png)

| Problem | Fix |
|---|---|
| `python` not found | Use `python3` on macOS/Linux or `py -3` on Windows. |
| `No module named aegis` | Run commands from the repository root (the folder that contains `aegis/`). |
| `Address already in use` | Use another port: `python -m aegis.web --open --port 8080`. |
| `AEGIS_APPROVAL_SECRET not set` warning | Harmless: a random key is used per run. Set it as shown in `.env.example` to silence it. |

## Protect your own agent

Send each tool call your agent proposes through the gateway instead of running
it directly:

```python
result = gateway.submit({"tool": "send_email", "args": {...}}, session, RiskReport(0.0))
result.for_agent()   # {"status": "denied", "rule_ids": ["P005", "P007", ...], "explanation": [...]}
```

[examples/protect_my_agent.py](examples/protect_my_agent.py) is a complete,
runnable example: an agent is told by an email to send the payroll file to an
outsider, and Aegis blocks it while the legitimate reply still goes through.
Any OpenAI-compatible API or a local [Ollama](https://ollama.com) model can be
driven through `aegis/agent/llm_agent.py`; configure it in `.env` (see
`.env.example`).

## How it decides

1. **Is the request well-formed?** Unknown tools, extra fields, path tricks
   and look-alike characters are rejected.
2. **Does the task allow it?** The user's task fixes the tools, files and
   recipients. Nothing the agent reads can widen this.
3. **May this data go there?** Once confidential data has been read, it can
   never be emailed outside the organisation, however the agent rewords it.
4. **Does a person need to approve?** Approval is bound to the exact action; if
   the agent changes one field afterwards, the approval is cancelled.
5. **Log it, then run it.** Every decision goes to a tamper-evident audit log.
   If the log can't be written, the action doesn't run. Any error means "no".

## Verification

- **320+ automated tests**, run in CI on Python 3.10–3.13 (also tested on 3.14).
- **Mutation testing:** 26 deliberately planted security bugs, all 26 caught.
- **Fast:** a decision takes about 0.08 ms (median, audit log included), so Aegis
  adds no noticeable delay to an agent (`python scripts/measure_latency.py`).
- **Randomised invariants:** a compromised agent sends random, malformed and
  hostile calls, replays and swaps approval tokens, with a human who approves
  everything. No forbidden action executes.
- **Methodological freeze:** fingerprints of the policy and detector were
  recorded before the held-out attacks were written; a test fails if they change.

```bash
python -m pip install pytest
python -m pytest                    # full test suite
python -m aegis.eval                # four-way benchmark
python scripts/mutation_check.py    # plant 26 bugs, confirm the tests catch them
python scripts/eval_real_emails.py  # real-email evaluation (needs the Kaggle dataset)
```

Optional install: `python -m pip install ".[ml]"` adds scikit-learn and the
`aegis-dashboard` and `aegis-benchmark` commands.

## Limits

Aegis controls which actions run and where data goes. It does not stop an
injection from changing the wording of a message the user already allowed, and
it can't protect against a person who approves a harmful action shown to them.
The tools in this repository are simulated, and the benchmark scenarios are
synthetic. Full details: [docs/threat_model.md](docs/threat_model.md).

## Documentation

| | |
|---|---|
| [docs/explainer.md](docs/explainer.md) | Full plain-language reference |
| [docs/threat_model.md](docs/threat_model.md) | What is in and out of scope |
| [docs/architecture.md](docs/architecture.md) | Security-core internals |
| [docs/benchmark.md](docs/benchmark.md) · [results](docs/benchmark_results.md) | Benchmark method and results |
| [docs/real_email_results.md](docs/real_email_results.md) | Classifier on real email |
| [docs/email_classifier.md](docs/email_classifier.md) | Classifier design and synthetic-corpus results |
| [docs/dashboard.md](docs/dashboard.md) | Dashboard and HTTP API |
| [docs/report.md](docs/report.md) | Technical report |
| [docs/pitch.md](docs/pitch.md) · [docs/demo_script.md](docs/demo_script.md) | Pitch, Q&A and live-demo script |
| [docs/aegis_judge_guide_hinglish.pdf](docs/aegis_judge_guide_hinglish.pdf) | Complete team guide in Hinglish: how it works and runs, file map, CI, training, history, edge cases, 68 judge Q&A |

## Prior work

Aegis is an engineering implementation of established ideas:
tool-level privilege policies ([Progent](https://arxiv.org/abs/2504.11703)),
control/data separation ([CaMeL](https://arxiv.org/abs/2503.18813)),
[design patterns for securing LLM agents](https://arxiv.org/abs/2506.08837), and
the evaluation approach of [AgentDojo](https://arxiv.org/abs/2406.13352).

## License

MIT. See [LICENSE](LICENSE).
