# Dashboard

A browser UI for demonstrating and exploring Aegis. It has **no third-party
dependencies**: a standard-library HTTP server (`http.server`) and a vanilla
JavaScript frontend. It drives the same gateway, approvals, detector and agent
as the benchmark, so what it shows is what the enforcement code actually does.

## Run it

```bash
python -m aegis.web --open          # opens http://127.0.0.1:8000
python -m aegis.web --port 8080     # if port 8000 is busy
```

On Windows you can double-click `start_demo.bat`; on macOS/Linux run
`./start_demo.sh`. For a browser-free transcript of the API and the headline
attack: `python scripts/demo_dashboard_flow.py`.

## Pages

- **Overview**: the problem, why scanning text is not enough, and what Aegis
  does instead.
- **Guided demo**: five scenarios, each run side by side (for example without
  protection vs. with Aegis), with the outcome, every step the assistant tried,
  the Aegis checkpoint for the key action, and what actually left the system.
- **Scoreboard**: the email classifier's results on a corpus, read from
  `results/scoreboard.json` (create it with
  `python scripts/scoreboard.py --json results/scoreboard.json`).
- **Test your own email**: upload an `.eml` file or paste text, choose who reads
  it (**Normal AI**: fooled, no protection; **Not-fooled AI**: ignores the
  email's instructions; **Aegis**: the fooled AI behind the gateway), and run it.
  The page shows the threat scanner and classifier verdicts, what the email tries
  to make the AI do, and the run. The **Break Aegis challenge** banner keeps a
  live tally of attack emails tried against Aegis and how many got through. The
  simulated assistant understands English, Hinglish and Hindi requests and
  obfuscated addresses or words (`x at evil dot com`, `s-a-l-a-r-y`).
- **Try it yourself**: pick any of the 31 scenarios, a protection setting and an
  approver, including **You decide**, where you approve or reject each send.
- **Results**: the four-way benchmark, run live when the page first opens, plus
  the classifier's results on real email.
- **How it's built**: the five checks every action passes and how the project
  is verified.

**Presentation mode** (top bar) enlarges everything for projectors and is
remembered across reloads.

## API (all JSON)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/meta` | configurations, approvers, and scenarios per split |
| POST | `/api/session` | start a run `{scenario_id, config, approver}`; returns a snapshot |
| POST | `/api/session/decide` | `{session_id, request_id, approve}`; approve or reject a pending action |
| POST | `/api/compare` | run one scenario under two configurations `{scenario_id, left, right}` |
| POST | `/api/custom` | run a user-supplied email `{raw, task, agent}` with `agent` = `normal`, `careful` or `aegis` |
| GET | `/api/benchmark` | the full four-way benchmark (computed once, then cached) |
| GET | `/api/scoreboard` | the classifier scoreboard, if `results/scoreboard.json` exists |
| GET | `/api/challenge` | the Break Aegis tally and the files an attack can target |
| POST | `/api/challenge/reset` | reset the tally (body `{}`) |

## Server hardening

The demo server is deliberately careful: it binds to `127.0.0.1` by default;
accepts only `application/json` request bodies (which blocks cross-site form
posts) and rejects oversized ones; validates every input against allow-lists;
serves static files only from the bundled directory with a fixed set of
extensions; sends a strict Content-Security-Policy and security headers on every
response; never echoes internal error details; and caps and evicts sessions. The
frontend builds every element with `textContent`, so content from emails or tool
arguments cannot inject markup. It has no user accounts, so run it on a trusted
machine or network only (see [SECURITY.md](../SECURITY.md)).
