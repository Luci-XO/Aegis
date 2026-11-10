"""Standard-library HTTP server for the Aegis dashboard.

No third-party dependencies. It exposes a small JSON API over the interactive
session driver and serves the static frontend. It is a local demo tool and
binds to localhost by default.

Defensive choices (this is a security project, so the demo server is careful):
- Binds to 127.0.0.1 unless --host is given explicitly.
- Rejects request bodies larger than MAX_BODY.
- Validates every input against allow-lists before use.
- Serves static files only from the bundled static directory, with the final
  resolved path checked to stay inside it; only a fixed set of extensions.
- Never echoes internal error details to the client; logs them server-side.
- In-memory session store with a cap and FIFO eviction.

Benchmark results shown in the dashboard are computed on first request and
cached for the process lifetime.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import threading
from collections import OrderedDict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any

from aegis.agent.scenarios import load_scenarios
from aegis.web.interactive import AUTO_APPROVERS, UI_CONFIGS, InteractiveSession, SessionError

log = logging.getLogger("aegis.web")

MAX_BODY = 64 * 1024
MAX_UPLOAD = 512 * 1024  # uploaded emails
MAX_SESSIONS = 200
SESSION_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)
_STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}
_APPROVERS = ["manual", *AUTO_APPROVERS]


class SessionStore:
    def __init__(self, cap: int = MAX_SESSIONS) -> None:
        self._d: OrderedDict[str, InteractiveSession] = OrderedDict()
        self._cap = cap
        self._lock = threading.Lock()

    def create(self, scenario, config: str, approver: str) -> InteractiveSession:
        sid = secrets.token_hex(16)
        sess = InteractiveSession(sid, scenario, config, approver)
        with self._lock:
            self._d[sid] = sess
            while len(self._d) > self._cap:
                self._d.popitem(last=False)
        return sess

    def get(self, sid: str) -> InteractiveSession:
        with self._lock:
            sess = self._d.get(sid)
        if sess is None:
            raise SessionError("unknown or expired session")
        return sess


class _BenchmarkCache:
    def __init__(self) -> None:
        self._data: dict[str, Any] | None = None
        self._lock = threading.Lock()

    def get(self) -> dict[str, Any]:
        with self._lock:
            if self._data is None:
                from aegis.eval.benchmark import run_benchmark

                result = run_benchmark(("dev", "heldout"))
                self._data = {"metadata": result.metadata, "summaries": result.summaries,
                              "detector": {k: {kk: vv for kk, vv in v.items() if kk != "per_document"}
                                           for k, v in result.detector.items()},
                              "cases": [c.to_dict() for c in result.cases]}
            return self._data


# "Test your own email" choices: agent -> (protection config, is the assistant fooled?)
CUSTOM_AGENTS: dict[str, tuple[str, bool]] = {
    "normal": ("A_unprotected", True),   # fooled assistant, no protection
    "careful": ("A_unprotected", False),  # assistant that ignores the email's instructions
    "aegis": ("D_aegis", True),          # fooled assistant behind Aegis
}


class Challenge:
    """'Break Aegis' tally: attack emails people tried against Aegis, and how many got through.
    In memory only; it resets when the dashboard restarts (or via /api/challenge/reset)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.attempts = 0
        self.got_through = 0

    def record(self, attack_succeeded: bool) -> None:
        with self._lock:
            self.attempts += 1
            self.got_through += int(attack_succeeded)

    def reset(self) -> None:
        with self._lock:
            self.attempts = self.got_through = 0

    def snapshot(self) -> dict[str, Any]:
        from aegis.web.custom import target_files

        with self._lock:
            return {"attempts": self.attempts, "got_through": self.got_through, "targets": target_files()}


def _scoreboard_results() -> dict[str, Any]:
    """Scoreboard written by scripts/scoreboard.py --json results/scoreboard.json."""
    import os

    path = Path(os.environ.get("AEGIS_SCOREBOARD_RESULTS", "results/scoreboard.json"))
    if not path.is_file():
        return {"available": False}
    try:
        data: dict[str, Any] = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"available": False, "error": "results file could not be read"}
    return {"available": True, **data}



def _static_dir() -> Path:
    return Path(str(resources.files("aegis") / "web" / "static"))


class Handler(BaseHTTPRequestHandler):
    server_version = "AegisDashboard"
    protocol_version = "HTTP/1.1"
    store: SessionStore
    benchmark: _BenchmarkCache
    challenge: Challenge
    scenarios_by_split: dict[str, dict[str, Any]]

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info("%s - %s", self.address_string(), fmt % args)

    # -- helpers -----------------------------------------------------------

    def _security_headers(self) -> None:
        """Defence-in-depth headers sent on every response. The CSP forbids inline
        and third-party scripts, so even if untrusted content somehow reached the
        DOM it could not execute - which matches the frontend's own rule of only
        ever writing text through textContent."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'self'; style-src 'self'; "
                         "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
                         "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

    def _send_json(self, obj: Any, status: int = 200) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._send_json({"error": message}, status)

    def _read_json(self, limit: int = MAX_BODY) -> dict[str, Any]:
        # Requiring application/json blocks cross-site form posts: a browser can't send
        # this content type to another origin without a CORS preflight, which we never grant.
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            raise SessionError("requests must be sent as application/json")
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > limit:
            raise SessionError("missing or oversized request body")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise SessionError("body is not valid JSON") from None
        if not isinstance(data, dict):
            raise SessionError("body must be a JSON object")
        return data

    # -- routing -----------------------------------------------------------

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_HEAD(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        path = self.path.split("?", 1)[0]
        try:
            if method == "GET" and path in ("/", "/index.html"):
                return self._serve_static("index.html")
            if method == "GET" and path.startswith("/static/"):
                return self._serve_static(path[len("/static/"):])
            if method == "GET" and path == "/api/meta":
                return self._send_json(self._meta())
            if method == "GET" and path == "/api/scoreboard":
                return self._send_json(_scoreboard_results())
            if method == "GET" and path == "/api/benchmark":
                return self._send_json(self.benchmark.get())
            if method == "POST" and path == "/api/session":
                return self._create_session()
            if method == "POST" and path == "/api/session/decide":
                return self._decide()
            if method == "POST" and path == "/api/compare":
                return self._compare()
            if method == "POST" and path == "/api/custom":
                return self._custom()
            if method == "GET" and path == "/api/challenge":
                return self._send_json(self.challenge.snapshot())
            if method == "POST" and path == "/api/challenge/reset":
                self._read_json()  # requires a JSON body, so a plain cross-site form can't reset it
                self.challenge.reset()
                return self._send_json(self.challenge.snapshot())
            self._error(HTTPStatus.NOT_FOUND, "not found")
        except SessionError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception:
            log.exception("unhandled error for %s %s", method, path)
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error")

    # -- endpoints ---------------------------------------------------------

    def _meta(self) -> dict[str, Any]:
        out: dict[str, Any] = {"configs": UI_CONFIGS, "approvers": _APPROVERS, "splits": {}}
        for split, by_id in self.scenarios_by_split.items():
            out["splits"][split] = [
                {"id": s["id"], "label": s["label"], "category": s["category"],
                 "description": s["description"]}
                for s in by_id.values()
            ]
        return out

    def _create_session(self) -> None:
        data = self._read_json()
        scenario_id = data.get("scenario_id")
        config = data.get("config")
        approver = data.get("approver")
        if not isinstance(config, str) or config not in UI_CONFIGS:
            raise SessionError("invalid config")
        if not isinstance(approver, str) or approver not in _APPROVERS:
            raise SessionError("invalid approver")
        scenario = self._find_scenario(scenario_id)
        sess = self.store.create(scenario, config, approver)
        self._send_json(sess.snapshot())

    def _decide(self) -> None:
        data = self._read_json()
        sid = data.get("session_id")
        request_id = data.get("request_id")
        approve = data.get("approve")
        if not isinstance(sid, str) or not SESSION_ID.fullmatch(sid):
            raise SessionError("invalid session id")
        if not isinstance(request_id, str) or not request_id:
            raise SessionError("invalid request id")
        if not isinstance(approve, bool):
            raise SessionError("'approve' must be true or false")
        sess = self.store.get(sid)
        sess.decide(request_id, approve)
        self._send_json(sess.snapshot())

    def _compare(self) -> None:
        """Run one scenario under two configurations with the careful simulated approver."""
        data = self._read_json()
        left, right = data.get("left"), data.get("right")
        if not isinstance(left, str) or not isinstance(right, str) or {left, right} - set(UI_CONFIGS):
            raise SessionError("invalid config")
        scenario = self._find_scenario(data.get("scenario_id"))
        out = {side: InteractiveSession(secrets.token_hex(16), scenario, cfg, "intent").snapshot()
               for side, cfg in (("left", left), ("right", right))}
        self._send_json(out)

    def _custom(self) -> None:
        """Run a user-supplied email through the chosen assistant."""
        from aegis.agent.scripted import ScriptedAgent
        from aegis.web.custom import CustomEmailError, analyze, build_custom_scenario, parse_email

        data = self._read_json(limit=MAX_UPLOAD)
        raw, task, agent = data.get("raw"), data.get("task", "reply"), data.get("agent", "normal")
        if agent not in CUSTOM_AGENTS:
            raise SessionError("agent must be one of: " + ", ".join(CUSTOM_AGENTS))
        try:
            email = parse_email(raw if isinstance(raw, str) else "")
            scenario, plan = build_custom_scenario(email, str(task))
        except CustomEmailError as exc:
            raise SessionError(str(exc)) from None
        config, fooled = CUSTOM_AGENTS[agent]
        # The not-fooled assistant does only the user's task: no injected actions.
        factory = None if fooled else ScriptedAgent
        run = InteractiveSession(secrets.token_hex(16), scenario, config, "intent", agent_factory=factory).snapshot()
        # Only a real attack run against Aegis counts toward the Break Aegis tally.
        if agent == "aegis" and scenario.label == "attack":
            self.challenge.record(bool(run["outcome"].get("attack")))
        self._send_json({"email": email, "plan": plan, "analysis": analyze(email), "agent": agent, "run": run,
                         "challenge": self.challenge.snapshot()})

    def _find_scenario(self, scenario_id: Any):
        if not isinstance(scenario_id, str):
            raise SessionError("invalid scenario id")
        for by_id in self.scenarios_by_split.values():
            if scenario_id in by_id:
                return by_id[scenario_id]["scenario"]
        raise SessionError("unknown scenario")

    def _serve_static(self, rel: str) -> None:
        root = _static_dir().resolve()
        target = (root / rel).resolve()
        if root != target and root not in target.parents:
            return self._error(HTTPStatus.FORBIDDEN, "forbidden")
        if target.suffix not in _STATIC_TYPES or not target.is_file():
            return self._error(HTTPStatus.NOT_FOUND, "not found")
        body = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", _STATIC_TYPES[target.suffix])
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


def build_handler_class() -> type[Handler]:
    scenarios_by_split: dict[str, dict[str, Any]] = {}
    for split in ("dev", "heldout"):
        _, scenarios = load_scenarios(split)
        scenarios_by_split[split] = {
            s.id: {"id": s.id, "label": s.label, "category": s.category,
                   "description": s.description, "scenario": s}
            for s in scenarios
        }

    class BoundHandler(Handler):
        pass

    BoundHandler.store = SessionStore()
    BoundHandler.benchmark = _BenchmarkCache()
    BoundHandler.challenge = Challenge()
    BoundHandler.scenarios_by_split = scenarios_by_split
    return BoundHandler


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    handler = build_handler_class()
    httpd = ThreadingHTTPServer((host, port), handler)
    log.info("Aegis dashboard on http://%s:%d (Ctrl-C to stop)", host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
