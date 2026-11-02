"""Publish your real-AI results so the deployed dashboard can show them.

    python scripts/run_real_ai_benchmark.py --limit 20     # on your laptop, with .env
    python scripts/publish_real_ai_results.py              # copies + checks the results
    git add aegis/data/published && git commit -m "Publish real-AI results" && git push

The dashboard reads results/real_ai/latest.json when it exists (your laptop)
and falls back to aegis/data/published/real_ai.json (the deployed site, which
never calls the model). This script copies one to the other after checks:

- it refuses results that contain your own emails (anything other than the
  built-in synthetic scenarios or corpus) unless you pass --include-own-emails,
  because the published file is public;
- it redacts anything that looks like an API key;
- it refuses a file with no successful runs.

Pass --scoreboard to also publish results/scoreboard.json.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLISHED = ROOT / "aegis" / "data" / "published"
BUILT_IN_SOURCES = {"scenarios", "corpus"}
KEY_PATTERNS = [
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),  # Google
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),  # OpenAI-style
]


def redact(text: str) -> tuple[str, int]:
    n = 0
    for pat in KEY_PATTERNS:
        text, k = pat.subn("[redacted]", text)
        n += k
    return text, n


def check_real_ai(data: dict, include_own: bool) -> list[str]:
    problems = []
    runs = data.get("runs") or []
    if not any(r.get("status") == "ok" for r in runs):
        problems.append("no successful runs in the file (only errors, or empty). Run the benchmark again.")
    own = sorted({c.get("source", "?") for c in data.get("cases", [])} - BUILT_IN_SOURCES)
    if own and not include_own:
        problems.append(
            "the results include emails from " + ", ".join(own) + ". The published file is public. "
            "Use only the built-in scenarios, or pass --include-own-emails if you're sure they can be shared."
        )
    return problems


def publish(src: Path, dest: Path, check=None) -> tuple[bool, str]:
    if not src.is_file():
        return False, f"{src} not found"
    raw = src.read_text("utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        return False, f"{src} is not valid JSON: {e}"
    problems = check(data) if check else []
    if problems:
        return False, "; ".join(problems)
    text, n = redact(raw)
    json.loads(text)  # redaction must not break the JSON
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, "utf-8")
    note = f" ({n} key-like strings redacted)" if n else ""
    return True, f"wrote {dest.relative_to(ROOT)}{note}"


def summary_lines(data: dict) -> list[str]:
    meta = data.get("meta", {})
    lines = [f"model {meta.get('model')} · run {meta.get('run_name')} · {len(data.get('cases', []))} emails"]
    for key, s in (data.get("summary") or {}).items():
        if s.get("runs"):
            lines.append(f"  {key:24} fooled {s['fooled_on_attacks']}/{s['attack_runs']} attacks · "
                         f"harm {s['harm_on_attacks']} · unauthorized execs {s['unauthorized_executions']}")
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", default=str(ROOT / "results" / "real_ai" / "latest.json"))
    ap.add_argument("--include-own-emails", action="store_true")
    ap.add_argument("--scoreboard", action="store_true", help="also publish results/scoreboard.json")
    a = ap.parse_args(argv)

    src = Path(a.src)
    ok, msg = publish(src, PUBLISHED / "real_ai.json", lambda d: check_real_ai(d, a.include_own_emails))
    print(("OK  " if ok else "NO  ") + msg)
    if ok:
        for line in summary_lines(json.loads((PUBLISHED / "real_ai.json").read_text("utf-8"))):
            print("    " + line)
    if a.scoreboard:
        ok2, msg2 = publish(ROOT / "results" / "scoreboard.json", PUBLISHED / "scoreboard.json")
        print(("OK  " if ok2 else "NO  ") + msg2)
        ok = ok and ok2
    if ok:
        print("\nNext: git add aegis/data/published && git commit -m \"Publish real-AI results\" && git push")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
