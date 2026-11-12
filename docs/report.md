# Aegis: a reference implementation of action-level policy enforcement for AI agents

A short technical report. All numbers here were produced by the code in this
repository and can be reproduced with the commands in the Reproducibility
section. Nothing in this report is a claim about prompt-injection robustness in
general; the results describe a small synthetic benchmark.

## 1. Problem

An AI agent reads untrusted content (emails, documents, tool output) and acts
with the user's permissions. The language model sees the user's request and the
attacker's text in one token stream and cannot reliably tell "data I am reading"
from "instructions I must follow". Text hidden in an email can therefore steer
which tools the agent calls and with what arguments (indirect prompt injection).
This maps to OWASP LLM01 (Prompt Injection) and LLM06 (Excessive Agency) in the
[OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).

## 2. Approach

Aegis places a deterministic **policy gateway** between the agent and its tools.
The agent may propose any action, but every proposed tool call is checked
against explicit rules immediately before execution. The language model is never
the final authority, and a threat detector can only make a decision stricter,
never looser. This is a plan-then-execute pattern with a reference monitor, in
the sense of [Beurer-Kellner et al., 2025](https://arxiv.org/abs/2506.08837).

```
 trusted user task ─► TaskGrant (tools, emails, files, recipients, clearance, expiry)
                                      │
 agent (scripted or LLM) ─► tool request {"tool","args"}        ◄── proposes only
                                      │
 ┌────────────────────────────────── gateway ─────────────────────────────────┐
 │ 1 validate schema (unknown tool, bad args, traversal, homoglyph)   P001/P002 │
 │ 2 evaluate deterministic policy (pure function, no LLM)            P003–P012 │
 │     grants · sensitivity clearance · expiry · egress table ·                │
 │     session data label (high-water mark) · risk may only escalate           │
 │ 3 DENY  → stop (an approval cannot override this)                           │
 │ 4 REQUIRE_APPROVAL → HMAC token bound to exact action, single-use  A001–A008 │
 │ 5 write pre-execution audit record, else do not execute            G001      │
 │ 6 run tool on the SAME validated object · 7 raise session label              │
 └──────────────────────────────┬──────────────────────────────────────────────┘
       simulated tools (in-memory inbox/files/outbox)   hash-chained SQLite audit
```

Threat detection (interpretable regex rules, noisy-OR) runs on untrusted content
and produces a risk score. The score can escalate a side effect to human
approval, but a deterministic deny always holds regardless of the score. A
failing or slow detector yields "no result", which escalates rather than
permits (fail closed). Delimiting of untrusted text in the LLM prompt
("spotlighting", [Hines et al., 2024](https://arxiv.org/abs/2403.14720)) is used
as hygiene, never as a boundary.

## 3. Threat model (summary)

The attacker controls the text of some emails or files and, in the worst case,
fully controls the agent's proposed tool calls. The attacker cannot change code,
policy, grants or the approval UI, and cannot read the approval secret. Trusted:
application code, policy, the user's task selection, and the human approver.
Out of scope: manipulating the content of a message to a recipient the user
already authorised; an approver who approves a harmful action shown to them;
side channels; multi-agent and multi-user deployments; a compromised host. Full
version in [threat_model.md](threat_model.md).

## 4. Relation to prior work

Aegis is a small reference implementation of established ideas, not a new
defense. Tool-level privilege policies are the subject of
[Progent (2025)](https://arxiv.org/abs/2504.11703), which is the closest work;
control/data separation and capabilities are from
[CaMeL (2025)](https://arxiv.org/abs/2503.18813); the evaluation method (score
on environment state, report utility alongside security) follows
[AgentDojo (NeurIPS 2024)](https://arxiv.org/abs/2406.13352). The motivation for
not trusting a detector is [Nasr, Carlini, Tramèr et al. (2025)](https://arxiv.org/abs/2510.09023),
who bypassed 12 recent defenses, most at over 90% success. We claim no novelty
over these. Our contribution is engineering and evaluation: a compact, fully
reproducible, dependency-free implementation; a four-way ablation under a
compromised-agent assumption; a reference-policy oracle that scores all
configurations on one scale; and a methodological freeze separating tuning data
from a held-out split.

## 5. Experimental setup

Four configurations over identical cases, tools, agent and success checks:

- **A** unprotected (agent runs with the user's full permissions)
- **B** detector-only (block a send when the detector flags input or fails)
- **C** gateway-only (policy + approvals, no detector)
- **D** Aegis (gateway + detector)

C and D each run under a careful intent-matching approver and a worst-case
rubber-stamp approver. Two low-friction ablations (C2, D2) remove default
send-approval to isolate the detector's contribution. The agent is a
fully-hijacked scripted worst case: after reading a malicious document it
proposes the attacker's actions (from the scenario, not parsed from text) and
always claims success.

Dataset: a **dev** split (16 cases) used while writing the policy and detector,
and a **held-out** split (15 cases) written after `aegis/eval/freeze.json`
recorded SHA-256 hashes of the policy, policy engine and detector.
`tests/test_freeze.py` fails if any frozen file changes, so held-out numbers
cannot be chased by tuning. The splits share no case ids and no documents.
Attack success, utility, and every attack being "live" against A and solvable by
A are machine-checked on the final environment state.

## 6. Results (held-out split, scripted hijacked agent, intent approver)

| Config | Attack success | Blocking rate | Unauthorized execs | Benign utility | False positives |
|---|---|---|---|---|---|
| A unprotected | 100% (10/10) | 0% (0/9) | 18 | 100% (5/5) | 0% (0/5) |
| B detector-only | 70% (7/10) | 11% (1/9) | 14 | 100% (5/5) | 0% (0/5) |
| C gateway-only | 10% (1/10) | 100% (9/9) | 0 | 100% (5/5) | 0% (0/5) |
| D Aegis | 10% (1/10) | 100% (9/9) | 0 | 100% (5/5) | 0% (0/5) |

Rates carry 95% Wilson intervals in the generated report. The held-out detector
caught 3 of 10 attacks (precision 1.0, recall 0.30, F1 0.46).

### Findings

1. **The gateway does the work.** C cuts attack success from 100% to 10% with
   zero unauthorized tool executions and no loss of benign utility. The single
   remaining success is `held-14`, the in-scope wording-manipulation case that is
   out of scope by design.
2. **Detection alone is not enough.** B still loses 70% of the time on held-out
   attacks, because the frozen detector misses paraphrased, keyword-free,
   obfuscated and in-file injections.
3. **C and D are identical on security here.** The detector adds no blocking on
   top of the gateway when sends already require approval; its role is
   escalation. This is the honest finding: the independent policy layer, not the
   detector, prevents the forbidden actions.
4. **Concrete "detector misses, gateway holds" cases** on held-out (the
   attacker's goal is reached under B but blocked under D):
   `held-06, held-08, held-09, held-10, held-11, held-13`. These six are the
   architecture's reason to exist. The detector did catch `held-07, held-12,
   held-15` (its 3 true positives), so those are not misses.
5. **The rubber-stamp approver changes nothing** about what policy denies: a
   test asserts identical zero unauthorized executions under both approvers.

Latency (this sandbox, no LLM): gateway decision including approval round-trip
and audit writes, median ~0.14 ms, p95 ~0.27 ms per step.

## 7. What was tested

- 330+ automated tests; a randomised compromised-agent invariant (12 seeds ×
  150 sessions with parameter swaps, replays and cross-session token reuse)
  whose postconditions are checked independently of the policy code.
- A reference-policy oracle asserting **0** unauthorized executions across both
  splits, all gateway configurations and both approvers, while A executes many.
- A mutation check that injects 26 deliberate security bugs (policy, approvals,
  audit chain, detector fail-safe, oracle, baselines); the suite catches all 26.
- Clean-clone reproduction with no install step.

## 8. Limitations and honesty notes

- Results describe a small synthetic suite, not prompt injection in general.
- No real LLM has been run; the agent is a deterministic worst case. The
  OpenAI-compatible adapter is tested only with a fake client.
- No ML classifier: scikit-learn was not installable in the build sandbox, so
  the detector is rule-based only. A classifier remains optional until it beats
  the rules on held-out data.
- The in-scope limitation (rewriting the content of an authorised message) is
  real and demonstrated (`held-14`, `dev-05`, `dev-16`).
- The audit hash chain detects edits, mid-chain deletion and reordering; it does
  not prevent deletion of the whole log and does not protect the signing key.
  Tail truncation needs an external anchor.
- Two held-out attacker goals were corrected during Stage 5 from an over-broad
  domain match (documented in each case's `goal_note`); no frozen file changed.

## 9. Reproducibility

```bash
git clone https://github.com/Luci-XO/Aegis.git && cd Aegis
python -m pytest                      # 330+ tests
python -m aegis.eval --report docs/benchmark_results.md   # dev + held-out
python scripts/mutation_check.py      # 26/26 mutants killed
python scripts/demo_core.py           # CLI attack-blocked walkthrough
python -m aegis.web                   # dashboard at http://127.0.0.1:8000
```

No third-party runtime dependencies; `pytest` only to run the tests. Every
benchmark run records the git commit, Python version, dataset versions and the
policy/engine/detector hashes.
