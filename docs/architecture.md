# Architecture (security core)

```
 trusted user task ──► TaskGrant (tools, emails, files, recipients, clearance, expiry)
                                   │
 agent (LLM or scripted) ──► raw request {"tool": ..., "args": {...}}   ◄── untrusted
                                   │
 ┌─────────────────────────────────▼──────────────────────────────────────┐
 │ Gateway.submit()                         aegis/core/gateway.py         │
 │  1. parse + validate schema   (tools/validation.py)        P001 P002   │
 │  2. policy.evaluate()  pure, deterministic (core/policy.py) P003-P012  │
 │       risk score may only escalate; exception → DENY        P000       │
 │  3. DENY → stop (approval cannot override)                             │
 │  4. REQUIRE_APPROVAL → create request, or redeem token      A001-A008  │
 │       (core/approvals.py: HMAC, single-use, expiry, exact hash)        │
 │  5. write execute_begin audit record, or stop               G001       │
 │  6. run handler on the SAME validated object (tools/registry.py)       │
 │  7. raise session label to the data's sensitivity, log outcome         │
 └─────────────────────────────────┬──────────────────────────────────────┘
                                   ▼
          SandboxEnv (in-memory inbox, files, drafts, outbox)
          AuditLog (SQLite, hash chain)  core/audit.py
```

## Key design choices

**Effects are fixed in code.** `send_email` is `EXTERNAL_SIDE_EFFECT` in the
tool registry. The policy file can disable a tool or require approval for it,
but cannot relabel it.

**Check what you execute.** Validation produces an immutable `ValidatedCall`
whose action hash covers session, tool and normalised arguments. The handler
receives that same object, so there is no gap between the checked values and
the executed values.

**Session label (high-water mark).** The gateway, not the agent, records the
sensitivity of all data returned in a session. Egress decisions use
`max(session label, attachment labels)`, so paraphrasing confidential content
does not bypass the rule.

**Egress table** (`aegis/policies/default.json`):

| data label | internal recipient | external recipient |
|---|---|---|
| public | allow | allow |
| internal | allow | require approval |
| confidential | require approval | **deny** |

The loader refuses any policy that sets `confidential → external` to `allow`.
On top of this table, `send_email` always requires approval in the default policy.

**Approval binding.** The token is `request_id.HMAC(secret, request_id | session | action_hash | expiry)`.
At redemption the gateway first re-runs policy (so a later denial wins), then
checks signature, status, expiry, session and exact hash. A mismatched action
revokes the approval.

## Rule IDs
See `aegis/core/rules.py` for the full catalogue. Every decision and audit
record references these IDs.
