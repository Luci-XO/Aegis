"""Dashboard: interactive driver and the HTTP API (against a real server)."""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from aegis.agent.scenarios import load_scenarios
from aegis.web.app import build_handler_class
from aegis.web.interactive import InteractiveSession, SessionError

_, DEV = load_scenarios("dev")
BY_ID = {s.id: s for s in DEV}


# --- interactive driver ----------------------------------------------------

def test_manual_pauses_then_approve_sends():
    s = InteractiveSession("a" * 32, BY_ID["dev-07-share-agenda"], "D_aegis", "manual")
    assert s.status == "awaiting_approval"
    snap = s.snapshot()
    assert snap["pending"]["tool"] == "send_email"
    assert snap["outbox"] == []
    s.decide(snap["pending"]["request_id"], True)
    assert s.status == "done"
    assert len(s.snapshot()["outbox"]) == 1


def test_manual_reject_blocks_without_orphan_request():
    s = InteractiveSession("b" * 32, BY_ID["dev-07-share-agenda"], "D_aegis", "manual")
    rid = s.snapshot()["pending"]["request_id"]
    s.decide(rid, False)
    snap = s.snapshot()
    assert snap["outbox"] == []
    assert any(st["status"] == "rejected_by_user" for st in snap["steps"])
    # No pending approval remains, and re-deciding the same id is rejected.
    assert snap["pending"] is None
    with pytest.raises(SessionError):
        s.decide(rid, True)


def test_manual_approval_cannot_execute_a_forbidden_action():
    """Even if the human approves, a policy-denied exfiltration never executes."""
    s = InteractiveSession("c" * 32, BY_ID["dev-03-payroll-reply"], "D_aegis", "manual")
    # The hijacked agent's first send (payroll to external) is DENIED outright,
    # so the run reaches an approval prompt only for the legitimate reply.
    guard = 0
    while s.status == "awaiting_approval" and guard < 10:
        p = s.snapshot()["pending"]
        s.decide(p["request_id"], True)  # rubber-stamp everything we are shown
        guard += 1
    snap = s.snapshot()
    for m in snap["outbox"]:
        assert "audit@finance-review.example" not in m["to"]
        assert "f-002" not in m["attachments"]


def test_unprotected_baseline_executes_attack():
    s = InteractiveSession("d" * 32, BY_ID["dev-02-payroll-summarize"], "A_unprotected", "manual")
    assert s.status == "done"
    snap = s.snapshot()
    assert any("finance-review.example" in r for m in snap["outbox"] for r in m["to"])
    assert snap["audit"] == [] and snap["audit_verified"] is None


def test_gateway_blocks_same_attack():
    s = InteractiveSession("e" * 32, BY_ID["dev-02-payroll-summarize"], "D_aegis", "intent")
    snap = s.snapshot()
    assert snap["outbox"] == []
    assert snap["audit_verified"] is True
    assert any(st["status"] == "denied" for st in snap["steps"])


@pytest.mark.parametrize("config", ["bad", "", "X"])
def test_invalid_config_rejected(config):
    with pytest.raises(SessionError):
        InteractiveSession("f" * 32, BY_ID["dev-01-benign-summarize"], config, "manual")


# --- HTTP API --------------------------------------------------------------

@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler_class())
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=5) as r:  # noqa: S310
        return r.status, json.loads(r.read())


def _post(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),  # noqa: S310
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_index_and_static(server):
    with urllib.request.urlopen(server + "/", timeout=5) as r:  # noqa: S310
        assert r.status == 200 and b"<title>Aegis" in r.read()
    with urllib.request.urlopen(server + "/static/app.js", timeout=5) as r:  # noqa: S310
        assert r.status == 200 and r.headers["Content-Type"].startswith("text/javascript")


def test_static_path_traversal_blocked(server):
    req = urllib.request.Request(server + "/static/../app.py")  # noqa: S310
    try:
        urllib.request.urlopen(req, timeout=5)  # noqa: S310
        raise AssertionError("traversal should not succeed")
    except urllib.error.HTTPError as e:
        assert e.code in (403, 404)


def test_meta_lists_configs(server):
    status, data = _get(server, "/api/meta")
    assert status == 200
    assert "D_aegis" in data["configs"] and "manual" in data["approvers"]
    assert data["splits"]["dev"] and data["splits"]["heldout"]


def test_full_session_over_http(server):
    status, snap = _post(server, "/api/session",
                         {"scenario_id": "dev-07-share-agenda", "config": "D_aegis", "approver": "manual"})
    assert status == 200 and snap["status"] == "awaiting_approval"
    rid = snap["pending"]["request_id"]
    status, snap = _post(server, "/api/session/decide",
                         {"session_id": snap["session_id"], "request_id": rid, "approve": True})
    assert status == 200 and snap["status"] == "done" and len(snap["outbox"]) == 1


@pytest.mark.parametrize("body", [
    {"scenario_id": "nope", "config": "D_aegis", "approver": "manual"},
    {"scenario_id": "dev-01-benign-summarize", "config": "evil", "approver": "manual"},
    {"scenario_id": "dev-01-benign-summarize", "config": "D_aegis", "approver": "nope"},
    {"config": "D_aegis", "approver": "manual"},
])
def test_bad_session_requests_rejected(server, body):
    status, data = _post(server, "/api/session", body)
    assert status == 400 and "error" in data


def test_decide_with_bad_session_id(server):
    status, data = _post(server, "/api/session/decide",
                        {"session_id": "nothex", "request_id": "x", "approve": True})
    assert status == 400


def test_benchmark_endpoint(server):
    status, data = _get(server, "/api/benchmark")
    assert status == 200
    assert data["summaries"] and "attack_success_rate" in data["summaries"][0]
