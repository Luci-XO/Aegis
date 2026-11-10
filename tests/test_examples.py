"""The integration example in examples/ must keep working and keep blocking the attack."""

from __future__ import annotations

import runpy
from pathlib import Path

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "protect_my_agent.py"


def test_protect_my_agent_example_blocks_the_attack(capsys):
    ns = runpy.run_path(str(EXAMPLE), run_name="__main__")
    out = capsys.readouterr().out
    sent = [(m.to, m.attachments) for m in ns["env"].outbox]
    assert sent == [(("raj.patel@aegis-corp.example",), ("f-007",))]  # only the legitimate send
    assert "send_email  -> denied" in out and "Audit log intact: True" in out
