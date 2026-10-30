"""Strict validation of untrusted tool-call requests.

Agent output is untrusted. A request is accepted only if it has exactly the
expected shape: a known tool name, only declared argument names, correct types,
bounded lengths and allow-listed character patterns. Values are normalised
(for example, e-mail addresses are lower-cased) before policy evaluation, so
the policy sees the same values the tool will execute with.

Error messages name the offending argument but never echo its value, because
values may contain secrets and error messages are written to the audit log.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from aegis.core.canonical import sha256_hex
from aegis.core.schemas import ArgValue

_TOOL_NAME = re.compile(r"[a-z_]{1,32}", re.ASCII)
_ARG_NAME = re.compile(r"[a-z_]{1,32}", re.ASCII)
# Control characters other than tab and newline are rejected in free text.
_BAD_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

EMAIL_ID = re.compile(r"e-\d{3}", re.ASCII)
FILE_ID = re.compile(r"f-\d{3}", re.ASCII)
# ASCII-only on purpose: rejects homoglyph addresses (e.g. a Cyrillic letter that looks like "a").
ADDRESS = re.compile(r"[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+", re.ASCII)

AuditMode = Literal["keep", "hash", "domain"]


class ValidationError(ValueError):
    """Raised when a request does not match the tool schema."""


@dataclass(frozen=True)
class ArgSpec:
    kind: Literal["str", "str_list"]
    required: bool = True
    max_len: int = 200
    pattern: re.Pattern[str] | None = None
    min_items: int = 0
    max_items: int = 10
    lower: bool = False
    multiline: bool = False
    audit: AuditMode = "hash"


def _clean_str(name: str, value: object, spec: ArgSpec) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"argument '{name}' must be a string")
    text = value.strip().lower() if spec.lower else value
    if spec.pattern is not None:
        text = text.strip()
    if len(text) > spec.max_len:
        raise ValidationError(f"argument '{name}' exceeds {spec.max_len} characters")
    if _BAD_CONTROL.search(text) or (not spec.multiline and ("\n" in text or "\r" in text)):
        raise ValidationError(f"argument '{name}' contains forbidden control characters")
    if spec.pattern is not None and not spec.pattern.fullmatch(text):
        raise ValidationError(f"argument '{name}' has an invalid format")
    return text


def validate_args(
    tool: str, raw_args: object, specs: Mapping[str, ArgSpec]
) -> dict[str, ArgValue]:
    if not isinstance(raw_args, Mapping):
        raise ValidationError("'args' must be an object")
    for key in raw_args:
        if not isinstance(key, str) or not _ARG_NAME.fullmatch(key):
            raise ValidationError("argument names must be short lower-case identifiers")
        if key not in specs:
            raise ValidationError(f"unexpected argument '{key}' for tool '{tool}'")

    out: dict[str, ArgValue] = {}
    for name, spec in specs.items():
        if name not in raw_args:
            if spec.required:
                raise ValidationError(f"missing required argument '{name}'")
            out[name] = () if spec.kind == "str_list" else ""
            continue
        value = raw_args[name]
        if spec.kind == "str":
            out[name] = _clean_str(name, value, spec)
        else:
            if not isinstance(value, (list, tuple)):
                raise ValidationError(f"argument '{name}' must be a list")
            if len(value) > spec.max_items:
                raise ValidationError(f"argument '{name}' has more than {spec.max_items} items")
            items: list[str] = []
            for item in value:
                cleaned = _clean_str(name, item, spec)
                if cleaned not in items:  # de-duplicate, keep order
                    items.append(cleaned)
            if len(items) < spec.min_items:
                raise ValidationError(f"argument '{name}' needs at least {spec.min_items} item(s)")
            out[name] = tuple(items)
    return out


def parse_envelope(raw: object) -> tuple[str, object]:
    """Check the outer shape {"tool": str, "args": object}. Returns (tool, args)."""
    if not isinstance(raw, Mapping):
        raise ValidationError("request must be an object")
    if set(raw.keys()) != {"tool", "args"}:
        raise ValidationError("request must contain exactly the keys 'tool' and 'args'")
    tool = raw["tool"]
    if not isinstance(tool, str) or not _TOOL_NAME.fullmatch(tool):
        raise ValidationError("tool name must be a short lower-case identifier")
    return tool, raw["args"]


def safe_tool_label(raw: object) -> str | None:
    """A tool name that is safe to write to the audit log, or None."""
    if isinstance(raw, Mapping):
        tool = raw.get("tool")
        if isinstance(tool, str) and _TOOL_NAME.fullmatch(tool):
            return tool
    return None


def redact_args(args: Mapping[str, ArgValue], specs: Mapping[str, ArgSpec]) -> dict[str, object]:
    """Audit-safe summary of validated arguments. Free text is reduced to length and hash."""
    summary: dict[str, object] = {}
    for name, value in args.items():
        mode = specs[name].audit
        values = value if isinstance(value, tuple) else (value,)
        if mode == "keep":
            summary[name] = list(values) if isinstance(value, tuple) else value
        elif mode == "domain":
            summary[name] = sorted({v.rsplit("@", 1)[-1] for v in values})
        else:
            joined = "\x1f".join(values)
            summary[name] = {"len": len(joined), "sha256": sha256_hex(joined)[:16]}
    return summary
