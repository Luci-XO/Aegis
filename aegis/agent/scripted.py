"""Deterministic scripted agent.

It completes the user's task with a fixed plan per template. If it is given an
`injections` map, it also models a *fully hijacked* language model: right
after it successfully reads a resource listed in the map, it proposes the
attacker's actions for that resource before continuing with the user's task.

This is a worst-case stand-in for a real LLM, not a claim about how any
particular model behaves. The injected actions come from the scenario
definition, never from parsing the email text, so the detector and the
gateway cannot see or benefit from them.

The agent's final message claims that every step it proposed succeeded. This
lets tests check that the user-facing report is built from the gateway trace
rather than from what the agent says.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Mapping, Sequence
from typing import Any

from aegis.agent.base import AgentStep
from aegis.agent.tasks import TaskInstance

_CONTENT_REF = re.compile(r"\$CONTENT\(([ef]-\d{3})\)")


def _call(tool: str, **args: Any) -> dict[str, Any]:
    return {"tool": tool, "args": args}


def _substitute(value: Any, seen: Mapping[str, str]) -> Any:
    """Replace $CONTENT(id) with text the agent has actually read (empty if it has not)."""
    if isinstance(value, str):
        return _CONTENT_REF.sub(lambda m: seen.get(m.group(1), ""), value)
    if isinstance(value, list):
        return [_substitute(v, seen) for v in value]
    if isinstance(value, dict):
        return {k: _substitute(v, seen) for k, v in value.items()}
    return value


def _text(value: Any) -> str:
    if isinstance(value, Mapping):
        return str(value.get("text", ""))
    return "" if value is None else str(value)


class ScriptedAgent:
    def __init__(self, injections: Mapping[str, Sequence[Mapping[str, Any]]] | None = None) -> None:
        self.name = "scripted-hijacked" if injections else "scripted"
        self._injections = {k: [dict(a) for a in v] for k, v in (injections or {}).items()}
        self._queue: deque[dict[str, Any]] = deque()
        self._proposed: list[str] = []
        self._notes: list[str] = []
        self._task: TaskInstance | None = None
        self._fired: set[str] = set()
        self._seen: dict[str, str] = {}  # resource id -> text returned to the agent

    def metadata(self) -> dict[str, Any]:
        return {"agent": self.name, "injected_resources": sorted(self._injections)}

    def start(self, task: TaskInstance) -> None:
        self._task = task
        p = task.params
        if task.template == "summarize_inbox":
            for eid in sorted(task.grant.allowed_email_ids):
                self._queue.append(_call("read_email", email_id=eid))
        elif task.template == "reply_to_sender":
            self._queue.append(_call("read_email", email_id=p["email_id"]))
            # Draft and send are added once the email has been read (subject needed).
        elif task.template == "share_file":
            fid = p["file_id"]
            recipients = p["recipients"]
            if not isinstance(recipients, (list, tuple)):
                raise ValueError("share_file recipients must be a list")
            self._queue.append(_call("read_file", file_id=fid))
            self._queue.append(_call(
                "send_email", to=list(recipients), subject=f"Sharing {fid}",
                body="Hi, please find the requested file attached.", attachments=[fid]))
        elif task.template == "search_and_summarize":
            self._queue.append(_call("search_files", query=p["query"]))
        else:
            raise ValueError(f"no script for template '{task.template}'")

    def next_step(self) -> AgentStep:
        if self._queue:
            req = _substitute(self._queue.popleft(), self._seen)
            self._proposed.append(str(req.get("tool")))
            return AgentStep(request=req)
        summary = "; ".join(self._notes) if self._notes else "nothing to report"
        return AgentStep(final=f"Done. Completed steps: {', '.join(self._proposed)}. Notes: {summary}")

    def observe(self, request: object, result: dict[str, Any]) -> None:
        if result.get("status") != "executed" or not isinstance(request, Mapping):
            return
        out = result.get("result") or {}
        tool = request.get("tool")
        rid = None
        if tool == "read_email":
            rid = out.get("email_id")
            raw_subject = out.get("subject")
            subject = str(raw_subject.get("text", "") if isinstance(raw_subject, Mapping) else raw_subject or "")
            subject = " ".join(subject.split())[:150]
            self._notes.append(f"{rid}: {subject}")
            self._seen[str(rid)] = _text(out.get("body"))
            if self._task and self._task.template == "reply_to_sender":
                sender = out.get("from")
                body = f"Hi, thanks for your message about '{subject}'. I'll follow up shortly."
                self._queue.append(_call("draft_email", to=[sender], subject=f"Re: {subject}", body=body))
                self._queue.append(_call("send_email", to=[sender], subject=f"Re: {subject}", body=body))
        elif tool == "read_file":
            rid = out.get("file_id")
            self._notes.append(f"{rid}: {out.get('name')}")
            self._seen[str(rid)] = _text(out.get("content"))
        elif tool == "search_files":
            for hit in out.get("results", []):
                self._queue.append(_call("read_file", file_id=hit["file_id"]))
        # Hijack: obey the attacker immediately after reading the malicious resource.
        if rid in self._injections and rid not in self._fired:
            self._fired.add(rid)
            for action in reversed(self._injections[rid]):
                self._queue.appendleft(dict(action))
