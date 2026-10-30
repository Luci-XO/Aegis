"""Non-interactive transcript of the dashboard API over real HTTP.

Boots the server in-process on an ephemeral port, drives the manual-approval
flow for the payroll attack, and prints what the gateway did. Terminates on its
own. This documents the API without needing a browser.

    python scripts/demo_dashboard_flow.py
"""

from __future__ import annotations

import json
import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis.web.app import build_handler_class


def call(base, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(  # noqa: S310 - localhost ephemeral server
        base + path, data=data, method="POST" if body is not None else "GET",
        headers={"Content-Type": "application/json"} if body is not None else {})
    with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310
        return json.loads(r.read())


def main() -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler_class())
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        meta = call(base, "/api/meta")
        print("configs :", meta["configs"])
        print("approvers:", meta["approvers"])

        for config in ("A_unprotected", "D_aegis"):
            print(f"\n=== scenario dev-03-payroll-reply, config {config}, manual approver ===")
            snap = call(base, "/api/session",
                        {"scenario_id": "dev-03-payroll-reply", "config": config, "approver": "manual"})
            # Approve everything we are shown, to make the point that approval
            # still cannot execute a policy-denied action.
            guard = 0
            while snap["status"] == "awaiting_approval" and guard < 10:
                p = snap["pending"]
                print(f"  approval prompt: {p['tool']} {json.dumps(p['display']['args'])[:70]}...")
                snap = call(base, "/api/session/decide",
                            {"session_id": snap["session_id"], "request_id": p["request_id"], "approve": True})
                guard += 1
            for st in snap["steps"]:
                rules = ",".join(r["rule_id"] for r in st["reasons"])
                print(f"  step {st['index']}: {st['tool']:<12} -> {st['status']:<16} [{rules}]")
            print(f"  outbox: {[(m['to'], m['attachments']) for m in snap['outbox']]}")
            print(f"  audit verified: {snap['audit_verified']}   agent claim: {snap['agent_claim']!r}")
            leaked = any('finance-review' in r for m in snap['outbox'] for r in m['to'])
            print(f"  >> payroll reached attacker: {leaked}")
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    main()
