"""Sanity check that the security tests are not vacuous.

Copies the repository to a temporary directory, injects one deliberate security
bug at a time, and runs the test suite. Every mutant must cause at least one
failing test ("killed"). A surviving mutant means the tests miss that bug.

Usage: python scripts/mutation_check.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MUTANTS = [
    ("egress rule removed", "aegis/core/policy.py",
     "if flow is not Verdict.ALLOW:", "if False:"),
    ("recipient grant check removed", "aegis/core/policy.py",
     "if rcpt not in grant.allowed_recipients:", "if False:"),
    ("resource grant check removed", "aegis/core/policy.py",
     "if level is None or rid not in allowed:", "if level is None:"),
    ("clearance check removed", "aegis/core/policy.py",
     "if level > grant.max_read_sensitivity:", "if False:"),
    ("expiry check removed", "aegis/core/policy.py",
     "if grant.expires_at is not None and now >= grant.expires_at:", "if False:"),
    ("lookalike domains treated as internal", "aegis/core/policy.py",
     'return address.rsplit("@", 1)[-1] in self.org_domains',
     'return address.rsplit("@", 1)[-1].replace("0", "o") in self.org_domains'),
    ("send approval not required", "aegis/core/policy.py",
     "if tool_policy.require_approval:", "if False:"),
    ("low risk lowers verdict", "aegis/core/policy.py",
     "    return Decision.from_reasons(reasons, call.action_hash)\n",
     "    if risk is not None and risk.score == 0.0:\n        return Decision.from_reasons([], call.action_hash)\n"
     "    return Decision.from_reasons(reasons, call.action_hash)\n"),
    ("approval hash binding removed", "aegis/core/approvals.py",
     "if not hmac.compare_digest(call.action_hash, req.action_hash):", "if False:"),
    ("approval not single-use", "aegis/core/approvals.py",
     "req.status = ApprovalStatus.USED", "req.status = ApprovalStatus.APPROVED"),
    ("approval session check removed", "aegis/core/approvals.py",
     "if call.session_id != req.session_id:", "if False:"),
    ("approval expiry removed", "aegis/core/approvals.py",
     "            if now >= req.expires_at:\n                return RedeemResult(False, request_id, \"A006\")",
     "            pass"),
    ("approval overrides deny", "aegis/core/gateway.py",
     "if decision.verdict is Verdict.DENY:", "if decision.verdict is Verdict.DENY and approval_token_absent(token):"),
    ("policy exception fails open", "aegis/core/gateway.py",
     'decision = Decision(Verdict.DENY, (_reason("P000"),), call.action_hash)',
     'decision = Decision(Verdict.ALLOW, (), call.action_hash)'),
    ("audit failure ignored", "aegis/core/gateway.py",
     "        except AuditError:\n            return self._result(",
     "        except AuditError:\n            pass\n        if False:\n            return self._result("),
    ("session label not updated", "aegis/core/session.py",
     "self._label = max(self._label, result_label)", "pass"),
    ("homoglyph addresses accepted", "aegis/tools/validation.py",
     'ADDRESS = re.compile(r"[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(\\.[a-z0-9-]{1,63})+", re.ASCII)',
     'ADDRESS = re.compile(r"[^@\\s]{1,64}@[^@\\s]{1,63}(\\.[^@\\s]{1,63})+")'),
    ("audit chain not checked", "aegis/core/audit.py",
     "            if _hash(prev_hash, body) != rhash:", "            if False:"),
    # Stage 4
    ("detector crash reported as safe", "aegis/detect/base.py",
     '            log.warning("detector %s raised", self.name, exc_info=True)\n            return None',
     '            return RiskReport(score=0.0, detector="crashed")'),
    ("missing detector result ignored in aggregate", "aegis/detect/base.py",
     "    if any(r is None for r in reports):\n        return None",
     "    if False:\n        return None"),
    ("untrusted content not delimited", "aegis/agent/llm_agent.py",
     '            return f"<<DATA {marker}>>\\n{text}\\n<</DATA {marker}>>"',
     "            return text"),
    ("user rejection ignored", "aegis/agent/runner.py",
     "if req is not None and self.approver.decide(req, task):",
     "if req is not None:"),
    ("subject treated as trusted", "aegis/tools/registry.py",
     '"subject": {"trust": "untrusted", "text": email.subject},',
     '"subject": email.subject,'),
]

HELPER = "\n\ndef approval_token_absent(token):\n    return token is None\n"


def main() -> int:
    # Optional: python scripts/mutation_check.py tests/test_invariants.py
    test_args = sys.argv[1:] or []
    survivors = []
    for name, rel, old, new in MUTANTS:
        with tempfile.TemporaryDirectory() as tmp:
            dst = Path(tmp) / "repo"
            shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
            target = dst / rel
            src = target.read_text(encoding="utf-8")
            if src.count(old) != 1:
                print(f"[ERROR ] {name}: pattern found {src.count(old)} times in {rel}")
                survivors.append(name)
                continue
            src = src.replace(old, new)
            if "approval_token_absent" in new:
                src += HELPER
            target.write_text(src, encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", *test_args],
                cwd=dst, capture_output=True, text=True,
            )
            killed = proc.returncode != 0
            print(f"[{'KILLED' if killed else 'SURVIVED':8}] {name}")
            if not killed:
                survivors.append(name)
    print(f"\n{len(MUTANTS) - len(survivors)}/{len(MUTANTS)} mutants killed")
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
