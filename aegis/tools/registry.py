"""Tool specifications and simulated implementations.

Each tool declares its effect class (read-only, local write, external side
effect) in code. The policy file can disable a tool or add approval
requirements, but cannot relabel a sending tool as read-only.

Handlers receive only validated, normalised arguments and the sandbox, and do
all validation before mutating state, so a failure leaves no partial effect.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from aegis.core.schemas import ArgValue, Effect, Sensitivity, TaskGrant
from aegis.tools.sandbox_env import OutgoingMessage, SandboxEnv
from aegis.tools.validation import ADDRESS, EMAIL_ID, FILE_ID, ArgSpec


@dataclass(frozen=True)
class ToolOutput:
    content: dict[str, Any]
    label: Sensitivity  # sensitivity of data returned to the agent


@dataclass(frozen=True)
class ToolContext:
    grant: TaskGrant


Handler = Callable[[SandboxEnv, Mapping[str, ArgValue], ToolContext], ToolOutput]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    effect: Effect
    description: str
    args: Mapping[str, ArgSpec]
    handler: Handler
    resource_args: Mapping[str, str]  # arg name -> "email" | "file"
    recipient_arg: str | None = None


class ToolError(RuntimeError):
    pass


def _read_email(env: SandboxEnv, args: Mapping[str, ArgValue], ctx: ToolContext) -> ToolOutput:
    email = env.emails[str(args["email_id"])]
    return ToolOutput(
        content={
            "email_id": email.id,
            "from": email.sender,  # mail-system metadata (treated as trusted in this simulation)
            # The subject is written by the sender, so it is as untrusted as the body.
            "subject": {"trust": "untrusted", "text": email.subject},
            # Marked so the agent layer can keep it out of the instruction channel.
            "body": {"trust": "untrusted", "text": email.body},
        },
        label=email.sensitivity,
    )


def _search_files(env: SandboxEnv, args: Mapping[str, ArgValue], ctx: ToolContext) -> ToolOutput:
    query = str(args["query"]).lower()
    hits = [
        {"file_id": f.id, "name": f.name, "sensitivity": f.sensitivity.name.lower()}
        for f in sorted(env.files.values(), key=lambda f: f.id)
        # Least privilege: search only covers files this task may read.
        if f.id in ctx.grant.allowed_file_ids
        and f.sensitivity <= ctx.grant.max_read_sensitivity
        and (query in f.name.lower() or any(query in t for t in f.tags))
    ]
    # Metadata only. Names are treated as internal information.
    label = Sensitivity.INTERNAL if hits else Sensitivity.PUBLIC
    return ToolOutput(content={"results": hits}, label=label)


def _read_file(env: SandboxEnv, args: Mapping[str, ArgValue], ctx: ToolContext) -> ToolOutput:
    f = env.files[str(args["file_id"])]
    return ToolOutput(
        content={
            "file_id": f.id,
            "name": f.name,
            "content": {"trust": "untrusted", "text": f.content},
        },
        label=f.sensitivity,
    )


def _message(env: SandboxEnv, args: Mapping[str, ArgValue], prefix: str, n: int) -> OutgoingMessage:
    attachments = tuple(args["attachments"])
    missing = [a for a in attachments if a not in env.files]
    if missing:
        raise ToolError("attachment does not exist")
    return OutgoingMessage(
        id=f"{prefix}-{n + 1:04d}",
        to=tuple(args["to"]),
        subject=str(args["subject"]),
        body=str(args["body"]),
        attachments=attachments,
    )


def _draft_email(env: SandboxEnv, args: Mapping[str, ArgValue], ctx: ToolContext) -> ToolOutput:
    msg = _message(env, args, "draft", len(env.drafts))
    env.drafts.append(msg)
    return ToolOutput(content={"draft_id": msg.id, "status": "drafted"}, label=Sensitivity.PUBLIC)


def _send_email(env: SandboxEnv, args: Mapping[str, ArgValue], ctx: ToolContext) -> ToolOutput:
    msg = _message(env, args, "msg", len(env.outbox))
    env.outbox.append(msg)  # simulated delivery: nothing leaves the process
    return ToolOutput(content={"message_id": msg.id, "status": "sent"}, label=Sensitivity.PUBLIC)


_MESSAGE_ARGS = {
    "to": ArgSpec(kind="str_list", max_len=254, pattern=ADDRESS, lower=True,
                  min_items=1, max_items=10, audit="domain"),
    "subject": ArgSpec(kind="str", max_len=200),
    "body": ArgSpec(kind="str", max_len=10_000, multiline=True),
    "attachments": ArgSpec(kind="str_list", required=False, max_len=5, pattern=FILE_ID,
                           max_items=5, audit="keep"),
}

_SPECS = [
    ToolSpec(
        name="read_email",
        effect=Effect.READ_ONLY,
        description="Read one email from the user's inbox.",
        args={"email_id": ArgSpec(kind="str", max_len=5, pattern=EMAIL_ID, audit="keep")},
        handler=_read_email,
        resource_args={"email_id": "email"},
    ),
    ToolSpec(
        name="search_files",
        effect=Effect.READ_ONLY,
        description="Search file names and tags in the permitted repository scope.",
        args={"query": ArgSpec(kind="str", max_len=100, lower=True)},
        handler=_search_files,
        resource_args={},
    ),
    ToolSpec(
        name="read_file",
        effect=Effect.READ_ONLY,
        description="Read one file from the repository.",
        args={"file_id": ArgSpec(kind="str", max_len=5, pattern=FILE_ID, audit="keep")},
        handler=_read_file,
        resource_args={"file_id": "file"},
    ),
    ToolSpec(
        name="draft_email",
        effect=Effect.LOCAL_WRITE,
        description="Save an email draft. Nothing is sent.",
        args=_MESSAGE_ARGS,
        handler=_draft_email,
        resource_args={"attachments": "file"},
    ),
    ToolSpec(
        name="send_email",
        effect=Effect.EXTERNAL_SIDE_EFFECT,
        description="Send an email (simulated outbox).",
        args=_MESSAGE_ARGS,
        handler=_send_email,
        resource_args={"attachments": "file"},
        recipient_arg="to",
    ),
]

TOOLS: Mapping[str, ToolSpec] = MappingProxyType({s.name: s for s in _SPECS})
