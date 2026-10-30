"""In-memory synthetic environment: inbox, file repository, drafts and outbox.

Evaluation checks this state (for example, "is the payroll file in the outbox?")
instead of trusting what the agent says it did.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from importlib import resources

from aegis.core.schemas import Sensitivity


@dataclass(frozen=True)
class Email:
    id: str
    sender: str
    to: tuple[str, ...]
    subject: str
    body: str
    sensitivity: Sensitivity


@dataclass(frozen=True)
class File:
    id: str
    name: str
    sensitivity: Sensitivity
    tags: tuple[str, ...]
    content: str


@dataclass
class OutgoingMessage:
    id: str
    to: tuple[str, ...]
    subject: str
    body: str
    attachments: tuple[str, ...]


@dataclass
class SandboxEnv:
    emails: dict[str, Email]
    files: dict[str, File]
    drafts: list[OutgoingMessage] = field(default_factory=list)
    outbox: list[OutgoingMessage] = field(default_factory=list)

    # ResourceCatalog interface used by the policy engine.
    def email_sensitivity(self, email_id: str) -> Sensitivity | None:
        e = self.emails.get(email_id)
        return e.sensitivity if e else None

    def file_sensitivity(self, file_id: str) -> Sensitivity | None:
        f = self.files.get(file_id)
        return f.sensitivity if f else None

    def clone(self) -> SandboxEnv:
        return copy.deepcopy(self)

    @staticmethod
    def from_dicts(emails: list[dict], files: list[dict]) -> SandboxEnv:
        e = {
            d["id"]: Email(
                id=d["id"],
                sender=d["sender"],
                to=tuple(d["to"]),
                subject=d["subject"],
                body=d["body"],
                sensitivity=Sensitivity.parse(d["sensitivity"]),
            )
            for d in emails
        }
        f = {
            d["id"]: File(
                id=d["id"],
                name=d["name"],
                sensitivity=Sensitivity.parse(d["sensitivity"]),
                tags=tuple(d.get("tags", ())),
                content=d["content"],
            )
            for d in files
        }
        if len(e) != len(emails) or len(f) != len(files):
            raise ValueError("duplicate ids in synthetic data")
        return SandboxEnv(emails=e, files=f)

    @staticmethod
    def default() -> SandboxEnv:
        base = resources.files("aegis") / "data" / "synthetic"
        emails = json.loads((base / "emails.json").read_text(encoding="utf-8"))
        files = json.loads((base / "files.json").read_text(encoding="utf-8"))
        return SandboxEnv.from_dicts(emails, files)
