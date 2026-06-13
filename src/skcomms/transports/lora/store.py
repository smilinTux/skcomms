"""Airtime budget + store-and-forward queue (spec §3, §6).

LoRa is duty-cycle limited. AirtimeBudget caps bytes per rolling window;
ForwardQueue holds frames that don't fit and drains them as budget frees. Time is
passed in (`now`) so it's deterministic + testable; the transport supplies a clock.
"""

from __future__ import annotations

import logging
from collections import deque

log = logging.getLogger(__name__)


class AirtimeBudget:
    # NOTE: for strict per-window duty-cycle compliance, `max_bytes` should be
    # ~half the legal airtime budget for the window. The window is tumbling
    # (not sliding), so two adjacent windows can transmit up to 2x max_bytes
    # across a boundary (M1); halving the cap keeps any sliding window legal.
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
    """Dest-aware airtime-bounded queue.

    Each item is a ``(frame, dest)`` tuple so frames for different recipients can
    interleave safely. ``drain`` returns the frames that fit the current window
    (bytes only, for the simple/legacy path); ``drain_with_dest`` returns the
    ``(frame, dest)`` pairs the transport needs to actually send.
    """

    def __init__(self, budget: AirtimeBudget) -> None:
        self._budget = budget
        self._q: deque[tuple[bytes, str | None]] = deque()

    def enqueue(self, frame: bytes, dest: str | None = None) -> None:
        self._q.append((frame, dest))

    def pending(self) -> int:
        return len(self._q)

    def drain_with_dest(self, *, now: float) -> list[tuple[bytes, str | None]]:
        """Pop + return as many head (frame, dest) pairs as the budget allows."""
        sent: list[tuple[bytes, str | None]] = []
        while self._q:
            frame, dest = self._q[0]
            if len(frame) > self._budget.max_bytes:
                # This frame can never fit any window's airtime budget. Drop it
                # rather than let it starve everything queued behind it forever.
                log.warning(
                    "dropping frame of %d bytes: exceeds per-window airtime "
                    "budget (max_bytes=%d) and can never be sent",
                    len(frame), self._budget.max_bytes,
                )
                self._q.popleft()
                continue
            if not self._budget.can_send(len(frame), now=now):
                break
            self._q.popleft()
            self._budget.record(len(frame), now=now)
            sent.append((frame, dest))
        return sent

    def drain(self, *, now: float) -> list[bytes]:
        """Pop + return as many head frames as the budget allows this window."""
        return [frame for frame, _ in self.drain_with_dest(now=now)]
