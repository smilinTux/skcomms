"""Airtime budget + store-and-forward queue (spec §3, §6).

LoRa is duty-cycle limited. AirtimeBudget caps bytes per rolling window;
ForwardQueue holds frames that don't fit and drains them as budget frees. Time is
passed in (`now`) so it's deterministic + testable; the transport supplies a clock.
"""

from __future__ import annotations

from collections import deque


class AirtimeBudget:
    def __init__(self, max_bytes: int, window_s: float) -> None:
        self.max_bytes = max_bytes
        self.window_s = window_s
        self._used = 0
        self._window_start = 0.0
        self._started = False

    def _roll(self, now: float) -> None:
        if not self._started:
            self._window_start = now
            self._started = True
        elif now - self._window_start >= self.window_s:
            self._window_start = now
            self._used = 0

    def can_send(self, nbytes: int, *, now: float) -> bool:
        self._roll(now)
        return self._used + nbytes <= self.max_bytes

    def record(self, nbytes: int, *, now: float) -> None:
        self._roll(now)
        self._used += nbytes


class ForwardQueue:
    def __init__(self, budget: AirtimeBudget) -> None:
        self._budget = budget
        self._q: deque[bytes] = deque()

    def enqueue(self, frame: bytes) -> None:
        self._q.append(frame)

    def pending(self) -> int:
        return len(self._q)

    def drain(self, *, now: float) -> list[bytes]:
        """Pop + return as many head frames as the budget allows this window."""
        sent: list[bytes] = []
        while self._q and self._budget.can_send(len(self._q[0]), now=now):
            frame = self._q.popleft()
            self._budget.record(len(frame), now=now)
            sent.append(frame)
        return sent
