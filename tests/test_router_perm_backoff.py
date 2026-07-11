"""Workstream B2: growing backoff for structurally-undeliverable rails.

RC2: a ``perm:`` failure (no route for THIS recipient) or a ``*`` broadcast on a
rail that cannot serve it does NOT arm the normal transient cooldown (that would
starve OTHER, deliverable recipients on an otherwise-healthy rail). But without
*any* backoff those attempts repeat every cycle. B2 adds a per-(rail, recipient)
backoff so a rail that keeps perm-failing to one recipient stops being
re-attempted for that recipient within a growing window, while remaining a full
candidate for every other recipient.
"""

from __future__ import annotations

import time

from skcomms.models import (
    MessageEnvelope,
    MessagePayload,
    RoutingConfig,
    RoutingMode,
)
from skcomms.router import Router
from skcomms.transport import (
    HealthStatus,
    SendResult,
    Transport,
    TransportCategory,
    TransportStatus,
)


class PermFailTransport(Transport):
    def __init__(self, name="https-s2s"):
        self.name = name
        self.priority = 1
        self.category = TransportCategory.REALTIME
        self.calls: list[str] = []
        self.result_error = "perm: no https-s2s inbox_url known for 'ghost'"
        self.succeed = False

    def configure(self, config: dict) -> None:  # pragma: no cover - trivial
        pass

    def is_available(self) -> bool:
        return True

    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:
        self.calls.append(recipient)
        return SendResult(
            success=self.succeed,
            transport_name=self.name,
            envelope_id="",
            latency_ms=0.0,
            error=None if self.succeed else self.result_error,
        )

    def receive(self) -> list[bytes]:  # pragma: no cover - unused
        return []

    def health_check(self) -> HealthStatus:  # pragma: no cover - unused
        return HealthStatus(transport_name=self.name, status=TransportStatus.AVAILABLE)


def _env(recipient):
    return MessageEnvelope(
        sender="lumina",
        recipient=recipient,
        payload=MessagePayload(content="x"),
        routing=RoutingConfig(mode=RoutingMode.FAILOVER),
    )


def test_perm_failure_backs_off_the_same_recipient():
    t = PermFailTransport()
    r = Router(transports=[t])

    # First attempt: rail is a candidate and perm-fails → records backoff.
    r._try_send(t, b"{}", "ghost")
    assert ("https-s2s", "ghost") in r._perm_backoff

    # Immediately re-selecting for the same recipient must skip the rail.
    names = [x.name for x in r._select_transports(RoutingMode.FAILOVER, _env("ghost"))]
    assert "https-s2s" not in names


def test_backoff_is_scoped_per_recipient():
    t = PermFailTransport()
    r = Router(transports=[t])

    r._try_send(t, b"{}", "ghost")  # back off 'ghost' only

    # A DIFFERENT recipient is unaffected — rail still offered.
    names = [x.name for x in r._select_transports(RoutingMode.FAILOVER, _env("realpeer"))]
    assert "https-s2s" in names


def test_backoff_window_grows_with_repeated_failures():
    t = PermFailTransport()
    r = Router(transports=[t])

    r._try_send(t, b"{}", "ghost")
    count1, _ = r._perm_backoff[("https-s2s", "ghost")]

    # Force the window to look elapsed, attempt again → count grows.
    r._perm_backoff[("https-s2s", "ghost")] = (count1, time.monotonic() - 10_000)
    assert r._in_perm_backoff("https-s2s", "ghost") is False  # window elapsed
    r._try_send(t, b"{}", "ghost")
    count2, _ = r._perm_backoff[("https-s2s", "ghost")]
    assert count2 == count1 + 1


def test_success_clears_backoff_for_that_recipient():
    t = PermFailTransport()
    r = Router(transports=[t])

    r._try_send(t, b"{}", "ghost")
    assert ("https-s2s", "ghost") in r._perm_backoff

    t.succeed = True
    r._try_send(t, b"{}", "ghost")
    assert ("https-s2s", "ghost") not in r._perm_backoff


def test_star_broadcast_failure_records_backoff():
    """A '*' send a rail cannot serve is treated like perm: it backs off '*'."""
    t = PermFailTransport(name="file")
    t.result_error = "cannot broadcast to '*'"
    r = Router(transports=[t])

    r._try_send(t, b"{}", "*")
    assert ("file", "*") in r._perm_backoff
