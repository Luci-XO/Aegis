"""Injectable clocks so expiry logic is testable without sleeping."""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> float:
        """Return the current time as Unix seconds."""
        ...


class SystemClock:
    def now(self) -> float:
        return time.time()


class FakeClock:
    """Manually advanced clock for tests."""

    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self._t = start

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("a clock cannot move backwards")
        self._t += seconds
