# Changelog

All notable changes to Aegis are recorded here. Versions follow
[Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-11

### Added
- Evaluation on **56,711 real emails** (Nazario phishing with Enron business
  mail, and TREC 2007 spam): 97.7% of real phishing and 99.7% of real spam
  stopped on held-out email. See `docs/real_email_results.md` and
  `scripts/eval_real_emails.py`.
- `examples/protect_my_agent.py`: how to put Aegis in front of an agent's tool
  calls, covered by a test.
- One-step launchers: `start_demo.bat` (Windows) and `start_demo.sh`
  (macOS/Linux), plus `python -m aegis.web --open`.
- Console commands `aegis-dashboard` and `aegis-benchmark` after
  `pip install .`.
- Lookalike-domain red flag (`paypa1`, `amaz0n`) and an optional hybrid
  rule mode for the email classifier.
- "Test your own email" lets you compare a normal AI, a not-fooled AI and
  Aegis on the same email.
- Content-Security-Policy and security headers on the dashboard; CI runs lint,
  type checks and tests on Python 3.10–3.13.

### Changed
- The scikit-learn backend scores in batches and supports `min_df`, which
  makes large evaluations fast (56k emails in about a minute).
- Results everywhere now lead with real-email numbers instead of synthetic
  ones.

### Removed
- The Gemini-specific integration and the dashboard's real-AI hooks. Any
  OpenAI-compatible or local (Ollama) model still plugs in through
  `aegis/agent/llm_client.py`.

## [0.1.0] — 2026-10

### Added
- Security core: policy gateway, task grants, egress control, approvals bound
  to the exact action, tamper-evident audit log, fail-closed error handling.
- Prompt-injection rule detector, scripted and LLM agents, scenario runner.
- Four-way benchmark (unprotected, detector-only, gateway-only, full) with a
  held-out split written after the rules were frozen.
- Browser dashboard, mutation testing (26/26 planted bugs caught), and
  randomised invariant tests.
