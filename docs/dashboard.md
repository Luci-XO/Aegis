# Dashboard (Stage 6)

A browser UI for exploring and demonstrating Aegis. It has **no third-party
dependencies**: a standard-library HTTP server (`http.server`) and a vanilla
JavaScript frontend. It drives the same gateway, approvals, detector and agent
as the benchmark, so what it shows is what the enforcement code actually does.

## Run it

```bash
python -m aegis.web          # then open http://127.0.0.1:8000
python -m aegis.web --port 8080
```

For a browser-free transcript of the API and the headline attack:

```bash
python scripts/demo_dashboard_flow.py
```

## Views

- **Live demo**: pick a scenario (dev or held-out), a configuration (A/B/C/D)
  and an approver (manual, intent, rubber_stamp, reject_all), then Run. You see
  the inbox and files (click an email to read its body and spot the hidden
  instruction), the agent's proposed actions each with the gateway verdict and
  rule ids, the detector risk applied, the approval prompt (in manual mode), the
  outbox of what actually left, the agent's unverified claim next to the truth,
  and the hash-chained audit trail.
- **Benchmark**: the four-way comparison table for both splits, computed on
  first open, with detector precision/recall/F1.
- **About**: a short explanation of the configurations and approvers.

## The manual-approval demo

With config **D_aegis** and approver **manual**, run `dev-03-payroll-reply`:

1. The hijacked agent reads the invoice email and proposes sending the payroll
   file to an external auditor. This is **denied outright** (P005 attachment not
   in grant, P007 recipient not granted); it never reaches you for approval.
2. The agent then makes its legitimate reply to the sender. That send needs
   approval; you see the exact recipient, subject and body and can approve it.
3. The outbox contains only the legitimate reply. The audit chain verifies.

Switch the config to **A_unprotected** and the same run sends the payroll file
to the attacker. That contrast is the point.

## API (all JSON)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/meta` | configurations, approvers, and scenarios per split |
| POST | `/api/session` | start a run `{scenario_id, config, approver}`; returns a snapshot |
| POST | `/api/session/decide` | `{session_id, request_id, approve}`; approve/reject a pending action |
| GET | `/api/benchmark` | the full four-way benchmark (cached) |

## Server hardening

Because this is a security project, the demo server is deliberately careful:
binds to `127.0.0.1` by default; rejects bodies over 64 KB; validates every
input against allow-lists; serves static files only from the bundled directory
with the resolved path checked to stay inside it and a fixed set of extensions;
never echoes internal error details to the client; caps and evicts sessions.
The frontend builds every element with `textContent`, so content from emails or
tool arguments cannot inject markup.
