"""Workstream B5: startup health-gate quarantine + periodic re-probe.

RC4 (dead rails logged forever): an enabled-but-unreachable rail (nostr bad
key, tailscale no-IP, webrtc broker down) failed every cycle because
``from_config`` registered any rail that was merely ``enabled`` +
constructible, with no startup health-gate. B5 quarantines a rail whose startup
``health_check()`` reports UNAVAILABLE: ``_select_transports`` skips it until a
periodic re-probe passes, at which point it rejoins selection.
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


class HealthScriptedTransport(Transport):
    def __init__(self, name="nostr", status=TransportStatus.UNAVAILABLE):
        self.name = name
        self.priority = 1
        self.category = TransportCategory.REALTIME
        self._status = status
        self.health_calls = 0

    def configure(self, config: dict) -> None:  # pragma: no cover - trivial
        pass

    def is_available(self) -> bool:
        return True

    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:  # pragma: no cover
        return SendResult(success=True, transport_name=self.name, envelope_id="", latency_ms=0.0)

    def receive(self) -> list[bytes]:  # pragma: no cover - unused
        return []

    def health_check(self) -> HealthStatus:
        self.health_calls += 1
        return HealthStatus(transport_name=self.name, status=self._status)


def _env(recipient="jarvis"):
    return MessageEnvelope(
        sender="lumina",
        recipient=recipient,
        payload=MessagePayload(content="x"),
        routing=RoutingConfig(mode=RoutingMode.FAILOVER),
    )


def test_quarantined_rail_is_skipped_by_selection():
    t = HealthScriptedTransport()
    r = Router(transports=[t])
    r.quarantine_transport(t.name)

    names = [x.name for x in r._select_transports(RoutingMode.FAILOVER, _env())]
    assert t.name not in names


def test_reprobe_releases_a_recovered_rail():
    t = HealthScriptedTransport(status=TransportStatus.UNAVAILABLE)
    r = Router(transports=[t])
    r.quarantine_transport(t.name)

    # Rail comes back; force the re-probe window to look elapsed.
    t._status = TransportStatus.AVAILABLE
    r._quarantined[t.name] = time.monotonic() - 10_000

    names = [x.name for x in r._select_transports(RoutingMode.FAILOVER, _env())]
    assert t.name in names
    assert t.name not in r._quarantined


def test_reprobe_keeps_still_dead_rail_quarantined():
    t = HealthScriptedTransport(status=TransportStatus.UNAVAILABLE)
    r = Router(transports=[t])
    r.quarantine_transport(t.name)
    r._quarantined[t.name] = time.monotonic() - 10_000

    names = [x.name for x in r._select_transports(RoutingMode.FAILOVER, _env())]
    assert t.name not in names
    assert t.name in r._quarantined


def test_quarantine_absent_health_check_does_not_crash():
    """A transport lacking health_check must never break selection (B5 says
    'don't crash if health_check absent')."""

    class NoHealth(Transport):
        name = "bare"
        priority = 1
        category = TransportCategory.FILE_BASED

        def configure(self, config): ...  # pragma: no cover
        def is_available(self): return True
        def send(self, b, r):  # pragma: no cover
            return SendResult(success=True, transport_name=self.name, envelope_id="", latency_ms=0.0)
        def receive(self): return []  # pragma: no cover
        def health_check(self):  # pragma: no cover
            raise AttributeError("no health check")

    t = NoHealth()
    r = Router(transports=[t])
    r.quarantine_transport(t.name)
    r._quarantined[t.name] = time.monotonic() - 10_000
    # Must not raise; the rail stays quarantined because the probe failed.
    names = [x.name for x in r._select_transports(RoutingMode.FAILOVER, _env())]
    assert t.name not in names
